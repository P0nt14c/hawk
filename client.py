# Hawk
# Author: Jason Howe
# CSEC 750
# Evil Bit C2

# client.py
# Client for Hawk

import lib
from scapy.all import IP, TCP, send

def wrap_ip(payload):
    ip_pkt = IP(src="127.0.0.1",dst="127.0.0.1")
    return ip_pkt/payload


def binary(input_string):
    bin_list = []
    for letter in input_string:
        bin = ''.join(format(ord(letter), '08b'))
        bin_list.append(bin)

    return bin_list


def convert(input):
    if input == "000":
        return 0
    elif input == "001" or input == "01":
        return 1
    elif input == "010":
        return 2
    elif input == "011":
        return 3
    elif input == "100":
        return 4
    elif input == "101":
        return 5
    elif input == "110":
        return 6
    elif input == "111":
        return 7


def send_msg(bin):

    for let in bin:
        int1 = convert(let[:2])
        int2 = convert(let[2:5])
        int3 = convert(let[5:])

        # payload = lib.create_pa()
        # payload.reserved = int1
        # pkt = wrap_ip(payload)
        # send(pkt)
        payload = lib.create_pa()
        payload.reserved = int2
        pkt = wrap_ip(payload)
        send(pkt)
        payload = lib.create_pa()
        payload.reserved = int3
        pkt = wrap_ip(payload)
        send(pkt)
    
    payload = lib.create_fin()
    pkt = wrap_ip(payload)
    send(pkt)
        

def main():
    # syn_payload = lib.create_syn()
    msg_str = input("Message>")
    msg_bin = binary(msg_str)
    send_msg(msg_bin)


    
   
    
    

main()
    