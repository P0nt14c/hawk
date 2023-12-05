# Hawk
# Author: Jason Howe
# CSEC 750
# Evil Bit C2

# lib.py
# common library functions for Hawk
import config



from scapy.all import TCP

# implement methods for SYN, SYN ACK, ACK, FIN

def set_payload(pkt: TCP, payload: bytes) -> TCP:
    pkt.reserved = payload
    return TCP


def create_syn() -> TCP:
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="S"
    )
    return pkt


def create_synack() -> TCP:
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="SA"
    )
    return pkt


def create_ack() -> TCP:
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="A"
    )
    return pkt


def create_fin() -> TCP:
    pkt = TCP(
        sport=config.SPORT,
        dport=9999,
        flags="F"
    )
    return pkt


def create_pa() -> TCP:
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




def create_conn():
    pass
    # send SYN
    # sniff for TCP on port... send to handle SYN/ACK
    # send ACK
    # send data
    # send FIN

def listen_conn():
    pass
    # sniff for TCP on port... send to handle SYN
    # send SYN/ACK
    # sniff for TCP on port... send to handle ACK
    # recieve data
    # wait for FIN
