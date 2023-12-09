from scapy.all import sniff, TCP

def handle_packet(packet):
    if TCP in packet and packet[TCP].dport == 9999:
        # Process the packet
        print(f"Received TCP packet on port 9999: {packet.summary()}")

# Sniff on localhost for port 9999
sniff(filter="tcp and port 9999", prn=handle_packet, iface="lo0", store=0)
