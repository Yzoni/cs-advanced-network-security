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


def test_acl():
    from modules.arp.arp_module import ACL
    acl_dict = {
        '00:11:22:aa:bb:cd': '10.10.10.2'
    }
    acl = ACL(acl_dict)
    assert acl.mac_ip_is_in_acl('00:11:22:aa:bb:cd', '10.10.10.2')
    assert not acl.mac_ip_is_in_acl('00:11:22:aa:bb:cd', '10.10.10.3')
    assert not acl.mac_ip_is_in_acl('00:11:22:aa:bb:ca', '10.10.10.2')


def test_acl_from_file():
    from modules.arp.arp_module import ACL

    p = Path('temp_test_acl_from_file.txt')
    with p.open(mode='w') as f:
        f.writelines(['10.0.0.1 11:ba:da:a5:55:11\n',
                      '10.0.0.2 11:ba:da:a5:55:11\n',
                      '192.168.178.5 11:8b:ad:f0:0d:11\n',
                      '12.12.12.12 11:de:fa:ce:d0:11\n'])

    acl = ACL.from_file(p)

    assert dict(acl.acl) == {
        '10.0.0.1': ['11:ba:da:a5:55:11'],
        '10.0.0.2': ['11:ba:da:a5:55:11'],
        '192.168.178.5': ['11:8b:ad:f0:0d:11'],
        '12.12.12.12': ['11:de:fa:ce:d0:11']
    }

    p.unlink()
