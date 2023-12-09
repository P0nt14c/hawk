from scapy.all import IP, TCP, send

def send_tcp_packet(destination_ip, destination_port):
    # Craft TCP packet
    tcp_packet = IP(dst=destination_ip) / TCP(dport=destination_port, flags="S")

    # Send the TCP packet
    response = send(tcp_packet)

    print(tcp_packet)
    print(f"Sent TCP packet to {destination_ip}:{destination_port}")
    # print(f"Received response: {response}")

# Example usage
destination_ip = "127.0.0.1"
destination_port = 9999

send_tcp_packet(destination_ip, destination_port)