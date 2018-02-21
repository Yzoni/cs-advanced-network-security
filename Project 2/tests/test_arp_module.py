from scapy.layers.l2 import Ether, ARP
import pytest

from ips_response import *

"""
dst= ff:ff:ff:ff:ff:ff
src= 00:11:22:aa:bb:cc
type= 0x806

hwtype= 0x1
ptype= 0x800
hwlen= 6
plen= 4
op= who-has
hwsrc= 00:11:22:aa:bb:cc
psrc= 172.16.20.40
hwdst= 00:00:00:00:00:00
pdst= 172.16.20.255
"""


@pytest.fixture
def arp():
    from arp_module import ARPModule
    return ARPModule()


def test_error_on_improperly_formatted_packet(arp):
    pass


def test_error_on_invalid_arp_mac_addresses(arp):
    a = ARP(hwsrc='aa')
    response = arp.receive_packet(a)
    assert type(response) is ErrorResponse

    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:00:00:00')
    response = arp.receive_packet(a)
    assert type(response) is ErrorResponse


def test_notice_on_request_not_sent_to_broadcast(arp):
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:11:22:aa:bb:ca', op='who-has')
    response = arp.receive_packet(a)
    assert type(response) is NoticeRespone


def test_notice_on_response_not_sent_to_unicast(arp):
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='ff:ff:ff:ff:ff:ff', op='is-at')
    response = arp.receive_packet(a)
    assert type(response) is NoticeRespone


def test_notice_on_inconsistent_linklayer_and_arp(arp):
    a = ARP(psrc='172.16.20.40')
    # print(a.summary())
