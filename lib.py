# Hawk
# Author: Jason Howe
# CSEC 750
# Evil Bit C2

# lib.py
# common library functions for Hawk
import config



from scapy.all import TCP

def set_payload(pkt: TCP, payload: bytes) -> TCP:
    # set the payload of the packet
    pkt.reserved = payload
    return TCP


def create_syn() -> TCP:
    # create SYN packet
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="S"
    )
    return pkt


def create_synack() -> TCP:
    # create SYNACK packet
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="SA"
    )
    return pkt


def create_ack() -> TCP:
    # create ACK packet
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="A"
    )
    return pkt


def create_fin() -> TCP:
    # create FIN packet
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="F"
    )
    return pkt


def create_pa() -> TCP:
    # create PUSH packet
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="PA"
    )
    return pkt


def handle_syn(packet):
    if TCP in packet and packet[TCP].flags == "S":
        print("[+] Recieved SYN Packet")


def handle_synack(packet):
    if TCP in packet and packet[TCP].flags == "SA":
        print("[+] Recieved SYN/ACK Packet")


def handle_ack(packet):
    if TCP in packet and packet[TCP].flags == "A":
        print("[+] Recieved ACK Request")




