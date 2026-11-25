from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import re

SSH_FAIL_RE = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)
AUTH_RE = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+\S+:\s+(?P<ev>LOGIN_FAILED|LOGIN_SUCCESS)\s+user=(?P<user>\S+)\s+ip=(?P<ip>\S+)"
)
NGINX_RE = re.compile(
    r'^(?P<ts>\S+)\s+\S+\s+nginx:\s+(?P<ip>\S+)\s+-\s+-\s+\[[^\]]+\]\s+"\S+\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d{3})'
)


def _ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    if m := SSH_FAIL_RE.match(line):
        return {"ts": _ts(m["ts"]), "type": "login_failed", "user": m["user"], "ip": m["ip"], "raw": line}
    if m := AUTH_RE.match(line):
        return {
            "ts": _ts(m["ts"]),
            "type": "login_failed" if m["ev"] == "LOGIN_FAILED" else "login_success",
            "user": m["user"],
            "ip": m["ip"],
            "raw": line,
        }
    if m := NGINX_RE.match(line):
        status = int(m["status"])
        return {
            "ts": _ts(m["ts"]),
            "type": "http_error" if status in (401, 403, 404, 429) or status >= 500 else "http_ok",
            "user": None,
            "ip": m["ip"],
            "path": m["path"],
            "raw": line,
        }
    return None


def detect_alerts(lines: list[str], fail_threshold: int = 5, window_minutes: int = 5) -> list[dict]:
    events = sorted((e for l in lines if (e := parse_line(l))), key=lambda x: x["ts"])
    win = timedelta(minutes=window_minutes)
    ip_fails, user_fails, ip_errs = defaultdict(deque), defaultdict(deque), defaultdict(deque)
    seen, alerts = set(), []

    for ev in events:
        ts, ip, user = ev["ts"], ev.get("ip"), ev.get("user")
        if ev["type"] == "login_failed":
            if ip:
                q = ip_fails[ip]
                q.append(ev)
                while q and ts - q[0]["ts"] > win:
                    q.popleft()
                if len(q) >= fail_threshold and ("bf", ip) not in seen:
                    seen.add(("bf", ip))
                    alerts.append({"severity": "HIGH", "rule": "Brute Force", "actor": ip, "count": len(q)})
            if user:
                uq = user_fails[user]
                uq.append(ev)
                while uq and ts - uq[0]["ts"] > win:
                    uq.popleft()
        elif ev["type"] == "login_success" and user:
            uq = user_fails[user]
            while uq and ts - uq[0]["ts"] > win:
                uq.popleft()
            if len(uq) >= 3 and ("pivot", user, ts.isoformat()) not in seen:
                seen.add(("pivot", user, ts.isoformat()))
                alerts.append({"severity": "CRITICAL", "rule": "Fail-to-Success Pivot", "actor": user, "count": len(uq)})
            uq.clear()
        elif ev["type"] == "http_error" and ip:
            wq = ip_errs[ip]
            wq.append(ev)
            while wq and ts - wq[0]["ts"] > timedelta(minutes=2):
                wq.popleft()
            if len(wq) >= 4 and ("scan", ip) not in seen:
                seen.add(("scan", ip))
                alerts.append({"severity": "MEDIUM", "rule": "HTTP Error Burst", "actor": ip, "count": len(wq)})
    return alerts


if __name__ == "__main__":
    demo = [
        "2026-11-25T12:00:01Z host1 sshd[10]: Failed password for root from 203.0.113.9 port 22 ssh2",
        "2026-11-25T12:00:05Z host1 sshd[11]: Failed password for root from 203.0.113.9 port 22 ssh2",
        "2026-11-25T12:00:09Z host1 sshd[12]: Failed password for root from 203.0.113.9 port 22 ssh2",
        "2026-11-25T12:00:13Z host1 sshd[13]: Failed password for root from 203.0.113.9 port 22 ssh2",
        "2026-11-25T12:00:17Z host1 sshd[14]: Failed password for root from 203.0.113.9 port 22 ssh2",
    ]
    for a in detect_alerts(demo):
        print(a)
