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
            self.acl = ACL.from_file(acl_conf)
        else:
            log.info('ALC not loaded')
            self.acl = None

        super().__init__()

    def receive_packet(self, pkt) -> IPSResponse:
        if not self.has_valid_arp_src_mac_address(pkt):
            return ErrorResponse('Packet has invalid ARP source MAC address', {})

        if not self.has_valid_arp_dst_mac_address(pkt):
            return ErrorResponse('Packet has invalid ARP destination MAC address', {})

        if self.acl and not self.acl.mac_ip_is_in_acl(pkt[ARP].hwsrc, pkt[ARP].psrc):
            return ErrorResponse('MAC-IP binding sender is not in ACL', {})

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


class ACL:
    """
    Access Control List

    Records possible IP to MAC bindings

     - An IP can have multiple possible MACs
     - A MAC can have multiple possible IPs
    """
    def __init__(self, acl: dict) -> None:
        self.acl = acl
        super().__init__()

    @classmethod
    def from_file(cls, acl_config: Path):
        with acl_config.open() as f:
            acl = defaultdict(list)
            for idx, l in enumerate(f):
                try:
                    l = l.rstrip()
                    ip = l.split(' ')[0]
                    mac = l.split(' ')[1]
                    acl[ip].append(mac)
                except KeyError:
                    log.error('ARP config failed to parse line {:d}'.format(idx))
        return cls(acl)

    def mac_ip_is_in_acl(self, mac, ip):
        if mac in self.acl and ip in self.acl[mac]:
            return True
        else:
            return False


