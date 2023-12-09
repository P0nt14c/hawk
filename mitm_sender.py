# Hawk
# Author: Jason Howe
# CSEC 750
# Evil Bit C2

# client.py
# Client for Hawk

import lib
from scapy.all import IP, TCP, send


def wrap_ip(payload):
    # wrap TCP packet in IP packet
    ## specify the source and dst here
    ip_pkt = IP(src="10.10.20.10", dst="192.168.1.239")
    return ip_pkt / payload


def binary(input_string):
    # convert characters to binary representation
    bin_list = []
    for letter in input_string:
        bin = "".join(format(ord(letter), "08b"))
        bin_list.append(bin)

    return bin_list


def convert(input):
    # convert binary to integers
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
    # handles sending the message
    for let in bin:
        # split into XX:XXX:XXX for sending
        int1 = convert(let[:2])  # this will always be 01 so we can ignore it
        int2 = convert(let[2:5])
        int3 = convert(let[5:])

        # send first int
        payload = lib.create_pa()
        payload.reserved = int2
        pkt = wrap_ip(payload)
        send(pkt)

        # send second int
        payload = lib.create_pa()
        payload.reserved = int3
        pkt = wrap_ip(payload)
        send(pkt)

    # since fin when done
    payload = lib.create_fin()
    pkt = wrap_ip(payload)
    send(pkt)


def main():
    # get message
    msg_str = input("Message>")

    # add the end string
    msg_str += "thompson"
    # convert message
    msg_bin = binary(msg_str)
    # send message
    send_msg(msg_bin)


main()
