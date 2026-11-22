import argparse
import hashlib
import json
import os
import time
from datetime import datetime

BASELINE_FILE = "fim_baseline.json"


def calculate_sha256(filepath: str) -> str | None:
    """Reads a file in 64KB chunks and returns its SHA-256 hex digest."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        return None


def scan_directory(target_dir: str) -> dict[str, str]:
    """Walks a directory and returns a dict of {filepath: sha256_hash}."""
    file_hashes = {}
    for root, _, files in os.walk(target_dir):
        for filename in files:
            filepath = os.path.abspath(os.path.join(root, filename))
            # Skip the baseline file itself if stored inside the target directory
            if os.path.basename(filepath) == BASELINE_FILE:
                continue
            file_hash = calculate_sha256(filepath)
            if file_hash:
                file_hashes[filepath] = file_hash
    return file_hashes


def create_baseline(target_dir: str) -> None:
    """Generates and saves the initial trusted baseline."""
    print(f"[*] Generating baseline for: {os.path.abspath(target_dir)}")
    hashes = scan_directory(target_dir)
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=4)
    print(f"[+] Baseline saved to '{BASELINE_FILE}' ({len(hashes)} files indexed).")


def log_alert(event_type: str, filepath: str) -> None:
    """Prints a timestamped security alert."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ALERT | {timestamp}] [{event_type}] {filepath}")


def monitor(target_dir: str, interval: int = 5) -> None:
    """Continuously monitors the directory against the saved baseline."""
    if not os.path.exists(BASELINE_FILE):
        print(f"[-] Error: '{BASELINE_FILE}' not found. Run with --baseline first.")
        return

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    print(f"[*] Monitoring '{os.path.abspath(target_dir)}' every {interval}s... (Press Ctrl+C to stop)")

    # Track already alerted states to prevent console spam on every loop
    alerted_modified = set()
    alerted_created = set()
    alerted_deleted = set()

    try:
        while True:
            current_state = scan_directory(target_dir)

            # 1. Check for Modified or Newly Created files
            for filepath, current_hash in current_state.items():
                if filepath not in baseline:
                    if filepath not in alerted_created:
                        log_alert("UNAUTHORIZED FILE CREATED", filepath)
                        alerted_created.add(filepath)
                elif baseline[filepath] != current_hash:
                    if filepath not in alerted_modified:
                        log_alert("FILE MODIFIED", filepath)
                        alerted_modified.add(filepath)
                else:
                    # File reverted back to original hash
                    alerted_modified.discard(filepath)

            # 2. Check for Deleted files
            for filepath in baseline:
                if filepath not in current_state:
                    if filepath not in alerted_deleted:
                        log_alert("FILE DELETED", filepath)
                        alerted_deleted.add(filepath)
                else:
                    alerted_deleted.discard(filepath)

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple SHA-256 File Integrity Monitor (FIM)")
    parser.add_argument("-d", "--dir", required=True, help="Target directory to monitor")
    parser.add_argument("-b", "--baseline", action="store_true", help="Create a new baseline")
    parser.add_argument("-m", "--monitor", action="store_true", help="Start monitoring against baseline")
    parser.add_argument("-i", "--interval", type=int, default=5, help="Scan interval in seconds (default: 5)")

    args = parser.parse_args()

    if args.baseline:
        create_baseline(args.dir)
    elif args.monitor:
        monitor(args.dir, args.interval)
    else:
        parser.print_help()
