from pathlib import Path

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
    from modules.arp.arp_module import ARPModule
    return ARPModule(acl_conf=None)


@pytest.fixture
def arp_acl():
    from modules.arp.arp_module import ARPModule
    return ARPModule(acl_conf=Path('example_acl_config.txt'))


def test_error_on_improperly_formatted_packet(arp):
    pass


def test_error_on_binding_to_broadcast(arp):
    a = ARP(hwsrc='ff:ff:ff:ff:ff:ff', hwdst='00:11:22:aa:bb:cc', op='is-at')
    response = arp.receive_packet(a)
    assert type(response) is ErrorResponse


def test_error_on_invalid_arp_mac_addresses(arp):
    # Invalid hwsrc
    a = ARP(hwsrc='aa')
    response = arp.receive_packet(a)
    assert type(response) is ErrorResponse

    # Invalid hwdst
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:00:00:00')
    response = arp.receive_packet(a)
    assert type(response) is ErrorResponse


def test_notice_on_request_not_sent_to_broadcast(arp):
    e = Ether(src='00:11:22:aa:bb:cd', dst='00:11:22:aa:bb:cc')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:11:22:aa:bb:ca', op='who-has')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone


def test_notice_on_response_not_sent_to_unicast(arp):
    e = Ether(src='00:11:22:aa:bb:cd', dst='ff:ff:ff:ff:ff:ff')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:00:00:00:00:00', op='is-at')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone


def test_notice_on_linklayer_address_matches_arp(arp):
    # Request
    e = Ether(src='00:11:22:aa:bb:cd')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:00:00:00:00:00', op='who-has')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone

    # Reply
    e = Ether(src='00:11:22:aa:bb:cd', dst='00:11:22:aa:bb:cc')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:11:22:aa:bb:cd', op='is-at')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone
