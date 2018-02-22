from pathlib import Path
from collections import defaultdict

from scapy.layers.l2 import ARP, Ether

from ips_module import IPSModule
from ips_response import *
from util import is_valid_mac_address
from ips_logger import log


class ARPModule(IPSModule):

    def __init__(self, acl_conf: (Path, None)) -> None:
        if acl_conf:
            self.acl = self._parse_acl_config(acl_conf)
        else:
            self.acl = None

        super().__init__()

    def receive_packet(self, pkt) -> IPSResponse:
        if not self.has_valid_arp_src_mac_address(pkt):
            return ErrorResponse('Packet has invalid ARP source MAC address', {})

        if not self.has_valid_arp_dst_mac_address(pkt):
            return ErrorResponse('Packet has invalid ARP destination MAC address', {})

        if self.acl and not self.packet_is_in_acl(pkt):
            return ErrorResponse('MAC address is not in ACL', {})

        if pkt[ARP].op == ARP.who_has:  # Request
            if not self.request_is_send_to_broadcast(pkt):
                return NoticeRespone('ARP Request is not to broadcast', {})
            if not self.request_linklayer_address_matches_arp(pkt):
                return NoticeRespone('Link layer MAC does not match ARP response MAC', {})
        else:  # Response
            if self.response_has_ip_bind_to_mac_broadcast(pkt):
                return ErrorResponse('ARP response tries to bind IP to MAC broadcast', {})
            if not self.response_is_send_to_unicast(pkt):
                return NoticeRespone('ARP Response is not to unicast', {})
            if not self.response_linklayer_address_matches_arp(pkt):
                return NoticeRespone('Link layer MAC does not match ARP response MAC', {})

        return PermittedResponse('Packet is all good', {})

    def _parse_acl_config(self, acl_config: Path) -> dict:
        with acl_config.open() as f:
            acl = defaultdict(list)
            for idx, l in enumerate(f):
                try:
                    ip = l.split(' ')[0]
                    mac = l.split(' ')[1]
                    acl[ip].append(mac)
                except KeyError:
                    log.error('ARP config failed to parse line {:d}'.format(idx))
        return acl

    def packet_is_in_acl(self, pkt):
        return True

    def response_has_ip_bind_to_mac_broadcast(self, pkt):
        return pkt[ARP].hwsrc == 'ff:ff:ff:ff:ff:ff'

    def response_linklayer_address_matches_arp(self, pkt):
        if pkt[ARP].hwsrc == pkt[Ether].src:
            return True

    def request_linklayer_address_matches_arp(self, pkt):
        if pkt[ARP].hwsrc == pkt[Ether].src and pkt[ARP].hwdst == pkt[Ether].dst:
            return True

    def response_is_send_to_unicast(self, pkt) -> bool:
        return pkt[Ether].hwdst != 'ff:ff:ff:ff:ff:ff'

    def request_is_send_to_broadcast(self, pkt) -> bool:
        return pkt[Ether].hwdst == 'ff:ff:ff:ff:ff:ff'

    def has_valid_arp_src_mac_address(self, pkt) -> bool:
        return is_valid_mac_address(pkt[ARP].hwsrc)

    def has_valid_arp_dst_mac_address(self, pkt) -> bool:
        return is_valid_mac_address(pkt[ARP].hwdst)

    def load_ip_to_mac_mappings(self):
        pass
