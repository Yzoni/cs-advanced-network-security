import argparse
from ips_logger import log

from scapy.layers.l2 import Ether
import pcap

from arp_module import ARPModule

arp_module = ARPModule()
TYPE_ARP = 2054


def packet_loop(pcap_file):
    sniffer = pcap.pcap(name=pcap_file, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        e = Ether(pkt)
        if e.type == TYPE_ARP:
            arp_module.receive_packet(Ether(pkt))


if __name__ == '__main__':
    log.info('IPS started')

    parser = argparse.ArgumentParser(description='IPS')
    parser.add_argument('pcap_in', type=str,
                        help='pcap file input or name of suitable network device')
    args = parser.parse_args()

    if args.pcap_in:
        pkts = packet_loop(args.pcap_in)
