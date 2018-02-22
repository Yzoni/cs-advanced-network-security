import argparse
from ips_logger import log
from pathlib import Path

from scapy.layers.l2 import Ether
import pcap

from modules.arp.arp_module import ARPModule

TYPE_ARP = 2054

if __name__ == '__main__':
    log.info('IPS started')

    parser = argparse.ArgumentParser(description='IPS')
    parser.add_argument('pcap_in', type=str,
                        help='pcap file input or name of suitable network device')
    parser.add_argument('log_out', type=str,
                        help='output file for a json log')
    parser.add_argument('--arp-config', dest='arp_config', type=str,
                        help='configuration file with IP to MAC bindings')
    args = parser.parse_args()

    if args.pcap_in and args.log_out:

        if args.arp_config:
            arp_module = ARPModule(acl_conf=Path(args.arp_config))
        else:
            arp_module = ARPModule(acl_conf=None)

        sniffer = pcap.pcap(name=args.pcap_in, promisc=True, immediate=True, timeout_ms=50)
        for ts, pkt in sniffer:
            e = Ether(pkt)
            if e.type == TYPE_ARP:
                arp_module.receive_packet(Ether(pkt))
