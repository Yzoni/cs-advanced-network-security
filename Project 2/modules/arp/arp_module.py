from pathlib import Path

from scapy.all import *

from ips_module import IPSModule
from ips_response import *
from util import is_valid_mac_address
from ips_logger import log
from modules.arp.arp_database import ARPDatabase


class ARPModule(IPSModule):

    def __init__(self, acl=None) -> None:
        if acl:
            assert isinstance(acl, ACL)
            self.acl = acl
        else:
            self.acl = None
            log().info('ARP ACL not loaded')

        self.db = ARPDatabase()

        super().__init__()

    def receive_packet(self, pkt) -> IPSResponse:
        if not self.has_valid_arp_src_mac_address(pkt):
            return ErrorResponse('Packet has invalid ARP source MAC address', {'pkt': repr(pkt)})

        if not self.has_valid_arp_dst_mac_address(pkt):
            return ErrorResponse('Packet has invalid ARP destination MAC address', {'pkt': repr(pkt)})

        if self.acl and not self.acl.mac_ip_is_in_acl(pkt[ARP].hwsrc, pkt[ARP].psrc):
            return ErrorResponse('MAC-IP binding sender is not in ACL', {'pkt': repr(pkt)})

        if pkt[ARP].op == ARP.who_has:  # Request
            if not self.request_mac_hwdst_is_not_zero(pkt):
                return NoticeRespone('Request ARP MAC address is not 00:00...', {'pkt': repr(pkt)})
            if self.db.request_sender_should_have_ip(pkt[ARP].hwsrc, pkt[ARP].pdst):
                return NoticeRespone('Requester should have known the IP already', {'pkt': repr(pkt)})
            if not self.is_send_to_broadcast(pkt):
                return NoticeRespone('ARP Request is not to broadcast', {'pkt': repr(pkt)})
            if not self.request_linklayer_address_matches_arp(pkt):
                return NoticeRespone('Link layer MAC does not match ARP request MAC', {'pkt': repr(pkt)})

        else:  # Reply
            if self.reply_has_ip_bind_to_mac_broadcast(pkt):
                return ErrorResponse('ARP reply tries to bind IP to MAC broadcast', {'pkt': repr(pkt)})
            if self.is_send_to_broadcast(pkt):
                return NoticeRespone('ARP reply is not to unicast', {'pkt': repr(pkt)})
            if not self.reply_linklayer_address_matches_arp(pkt):
                return NoticeRespone('Link layer MAC does not match ARP reply MAC', {'pkt': repr(pkt)})

        # The requester/replier should now know the requested ip-mac
        self.db.store_mac_should_know(pkt[ARP].hwsrc, pkt[ARP].pdst)

        return PermittedResponse('Packet is all good', {'pkt': repr(pkt)})

    def request_mac_hwdst_is_not_zero(self, pkt):
        return pkt[ARP].hwdst == '00:00:00:00:00:00'

    def reply_has_ip_bind_to_mac_broadcast(self, pkt):
        return pkt[ARP].hwsrc == 'ff:ff:ff:ff:ff:ff'

    def reply_linklayer_address_matches_arp(self, pkt):
        if pkt[ARP].hwsrc == pkt[Ether].src and pkt[ARP].hwdst == pkt[Ether].dst:
            return True

    def request_linklayer_address_matches_arp(self, pkt):
        if pkt[ARP].hwsrc == pkt[Ether].src:
            return True

    def is_send_to_broadcast(self, pkt) -> bool:
        return pkt.dst == 'ff:ff:ff:ff:ff:ff'

    def has_valid_arp_src_mac_address(self, pkt) -> bool:
        return is_valid_mac_address(pkt[ARP].hwsrc)

    def has_valid_arp_dst_mac_address(self, pkt) -> bool:
        return is_valid_mac_address(pkt[ARP].hwdst)


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
                    log().error('ARP config failed to parse line {:d}'.format(idx))
        return cls(acl)

    def mac_ip_is_in_acl(self, mac, ip):
        if mac in self.acl and ip in self.acl[mac]:
            return True
        else:
            return False
