from ips_module import IPSModule
from ips_response import *
from scapy.layers.l2 import ARP, Ether
from util import is_valid_mac_address

ARP_ACCESS_CONTROL_LIST = {}  # TODO replace with separate file, should allow more than 1 MAC address per IP


class ARPModule(IPSModule):
    def receive_packet(self, pkt) -> IPSResponse:
        if not self.has_valid_arp_src_mac_address(pkt):
            return ErrorResponse('a')

        if not self.has_valid_arp_dst_mac_address(pkt):
            return ErrorResponse('a')

        if not self.response_is_send_to_unicast(pkt):
            return NoticeRespone('a')

        if not self.request_is_send_to_broadcast(pkt):
            return NoticeRespone('a')

        if not self.linklayer_address_matches_arp(pkt):
            return NoticeRespone('a')

        return PermittedResponse('All permitted')

    def linklayer_address_matches_arp(self, pkt):
        if pkt[ARP].op == ARP.is_at and pkt[ARP].hwsrc == pkt[Ether].src and pkt[ARP].hwdst == pkt[Ether].dst:
            return True
        elif pkt[ARP].op == ARP.who_has and pkt[ARP].hwsrc == pkt[Ether].src:
            return True
        else:
            return False

    def response_is_send_to_unicast(self, pkt) -> bool:
        if pkt[ARP].op == ARP.is_at:
            return pkt[ARP].hwdst != '00:00:00:00:00:00'
        else:
            return True

    def request_is_send_to_broadcast(self, pkt) -> bool:
        if pkt[ARP].op == ARP.who_has:
            return pkt[ARP].hwdst == '00:00:00:00:00:00'
        else:
            return True

    def has_valid_arp_src_mac_address(self, pkt) -> bool:
        return is_valid_mac_address(pkt[ARP].hwsrc)

    def has_valid_arp_dst_mac_address(self, pkt) -> bool:
        return is_valid_mac_address(pkt[ARP].hwdst)

    def load_ip_to_mac_mappings(self):
        pass
