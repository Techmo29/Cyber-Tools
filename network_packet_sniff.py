from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]

        print("\n========== PACKET CAPTURED ==========")
        print("Source IP      :", ip_layer.src)
        print("Destination IP :", ip_layer.dst)
        print("Protocol       :", ip_layer.proto)
        print("Packet Size    :", len(packet), "bytes")

        if TCP in packet:
            print("Type           : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:
            print("Type           : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif ICMP in packet:
            print("Type           : ICMP")

        if DNS in packet and packet[DNS].qd:
            print("DNS Query      :", packet[DNS].qd.qname.decode(errors="ignore"))

        print("=====================================")


print("Network Packet Sniffer Started...")
print("Press CTRL+C to stop capturing packets.\n")

try:
    sniff(
        filter="ip",
        prn=packet_callback,
        store=False
    )

except KeyboardInterrupt:
    print("\nPacket Sniffer Stopped.")
