"""

Yorick de Boer

Modular Intrusion Prevention System (IPS)

"""

import argparse
from ips_logger import log, init_logger
from pathlib import Path

from scapy.layers.l2 import Ether
import pcap

from modules.arp.arp_module import ARPModule, ACL
from modules.ieee80211.ieee80211_module import IEEE80211Module

ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_IPV6 = 0x86DD
ETHER_TYPE_ARP = 0x0806

# DLT_ linktype http://www.tcpdump.org/linktypes.html
LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11_RADIOTAP = 127


def ether_loop(sniffer):
    if args.arp_config:
        arp_module = ARPModule(ACL.from_file(Path(args.arp_config)))
    else:
        arp_module = ARPModule()

    for ts, pkt in sniffer:
        e = Ether(pkt)
        try:
            if e.type == ETHER_TYPE_ARP:
                log().info('Received ARP packet')
                arp_module.receive_packet(e, ts)
            else:
                log().info('Received packet not supported by IPS')
        except AttributeError:
            log().info('Received packet does not have a type')
            continue


def radiotap_loop(sniffer):
    ieee80211_module = IEEE80211Module()

    pkt_c = 0
    for ts, pkt in sniffer:
        try:
            pkt_c += 1
            log().debug('Received IEEE80211 packet ({:d})'.format(pkt_c))
            ieee80211_module.receive_packet(pkt, pkt_c)
        except Exception as e:
            print(e)
            log().error('Could not parse IEEE80211 packet ({:d})'.format(pkt_c))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='IPS')
    parser.add_argument('pcap_in', type=str,
                        help='pcap file input or name of suitable network device')
    parser.add_argument('log_out', type=str,
                        help='output file for a json log')
    parser.add_argument('--arp-acl-config', dest='arp_config', type=str,
                        help='configuration file with IP to MAC bindings')
    args = parser.parse_args()

    if args.pcap_in and args.log_out:
        init_logger(args.log_out)

        log().info('IPS STARTED')

        sniffer = pcap.pcap(name=args.pcap_in, promisc=True, immediate=True, timeout_ms=50)
        datalink = sniffer.datalink()

        if LINKTYPE_ETHERNET == datalink:
            ether_loop(sniffer)
        elif LINKTYPE_IEEE802_11_RADIOTAP == datalink:
            radiotap_loop(sniffer)
        else:
            log().error('PCAP LINK LAYER TYPE NOT SUPPORTED: {:d}'.format(datalink))

        log().info('IPS STOPPED')
