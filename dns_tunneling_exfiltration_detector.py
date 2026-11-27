import math
import time
from collections import Counter, defaultdict
from scapy.all import sniff, DNS, DNSQR, IP

ENTROPY_THRESHOLD = 3.8
SUBDOMAIN_LENGTH_THRESHOLD = 30
QUERY_RATE_THRESHOLD = 15
TIME_WINDOW = 10

query_tracker = defaultdict(list)

def calculate_shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def extract_subdomain(qname):
    parts = qname.rstrip('.').split('.')
    if len(parts) > 2:
        return '.'.join(parts[:-2])
    return ""

def check_query_rate(src_ip, base_domain):
    now = time.time()
    key = (src_ip, base_domain)
    query_tracker[key] = [t for t in query_tracker[key] if now - t <= TIME_WINDOW]
    query_tracker[key].append(now)
    return len(query_tracker[key])

def process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(IP):
        if packet[DNS].qr == 0:
            src_ip = packet[IP].src
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            subdomain = extract_subdomain(qname)
            
            parts = qname.rstrip('.').split('.')
            base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else qname
            
            entropy = calculate_shannon_entropy(subdomain)
            sub_len = len(subdomain)
            rate = check_query_rate(src_ip, base_domain)
            
            reasons = []
            if sub_len > SUBDOMAIN_LENGTH_THRESHOLD:
                reasons.append(f"Length={sub_len}")
            if entropy > ENTROPY_THRESHOLD:
                reasons.append(f"Entropy={entropy:.2f}")
            if rate > QUERY_RATE_THRESHOLD:
                reasons.append(f"Rate={rate}/{TIME_WINDOW}s")
                
            if reasons:
                print(f"[ALERT] {src_ip} -> {qname.rstrip('.')} | {', '.join(reasons)}")

def main():
    print("Monitoring DNS traffic for tunneling/exfiltration...")
    sniff(filter="udp port 53", prn=process_packet, store=False)

if __name__ == "__main__":
    main()
