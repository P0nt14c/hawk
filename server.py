# Hawk
# Author: Jason Howe
# CSEC 750
# Evil Bit C2

# server.py
# C2 Server for Hawk

from scapy.all import sniff, TCP, IP, send
from textwrap import wrap
import lib

MSG_RAW = [""]
packet_counter = 0

def split_string_into_chunks(input_string, chunk_size=6):
    # This function will return a list of strings of size 6
    for i in range(0, len(input_string), chunk_size):
        yield input_string[i:i+chunk_size]

def binary_to_ascii(binary_string):
    # Convert binary string to integer
    decimal_value = int(binary_string, 2)

    # Convert integer to ASCII character
    ascii_character = chr(decimal_value)

    # return character
    return ascii_character


def parse(input):
    # split into chunks of 6
    chunks = wrap(input, 6)
    msg = []
    # add 01 to start of string to convert back to 8-bit ascii in binary representation
    for i in chunks:
        msg.append("01" + i)
    string = []
    # convert message to ascii
    for i in msg:
        string.append(binary_to_ascii(i))

    # turn it into a string
    final = ''.join(string)

    # print message
    print(final)


def convert(input):
    # turn ints into binary
    if input == 0:
        return "000"
    elif input == 1:
        return "001"
    elif input == 2:
        return "010"
    elif input == 3:
        return "011"
    elif input == 4:
        return "100"
    elif input == 5:
        return "101"
    elif input == 6:
        return "110"
    elif input == 7:
        return "111"

def wrap_ip(payload):
    # wrap TCP packet in IP packet
    ip_pkt = IP(src="127.0.0.1",dst="127.0.0.1")
    return ip_pkt/payload

def handle_packet(packet):
    # listen for packets, and handle data
    global MSG_RAW
    global packet_counter
    packet_counter += 1
    if packet_counter % 2 == 1:
        # if TCP in packet and packet[TCP].dport == 9999:
        if TCP in packet:
            # Process the packet
            if packet[TCP].flags == "F":
                #print("F", MSG_RAW)
                parse(MSG_RAW[0])
            elif packet[TCP].flags == "PA":
                MSG_RAW[0] += convert(packet[TCP].reserved)
            elif packet[TCP].flags == "S":
                # three way handshake
                payload = lib.create_synack()
                pkt = wrap_ip(payload)
                send(pkt)
            elif packet[TCP].flags == "SA":
                #three way handshake
                pass



def main():
    # listen for TCP packets and pass to packet handler
    sniff(filter="tcp", prn=handle_packet, iface="lo", store=0)


main()