from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  
            proto_name = "TCP"
        elif protocol == 17:  
            proto_name = "UDP"
        else:
            proto_name = "Other"

        payload = packet[IP].payload

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {proto_name}")
        print(f"Payload: {payload}")
        print("-" * 50)

# Start sniffing
sniff(prn=packet_callback, store=0)
