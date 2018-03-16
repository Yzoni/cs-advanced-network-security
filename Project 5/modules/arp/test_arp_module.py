from pathlib2 import Path

from scapy.all import *
import pytest

from ips_response import *
from modules.arp.arp_module import ACL


@pytest.fixture
def arp():
    from modules.arp.arp_module import ARPModule
    return ARPModule()


def test_notice_on_arp_hwdst_request_non_zero(arp):
    e = Ether(src='00:11:22:aa:bb:cc', dst='ff:ff:ff:ff:ff:ff')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:11:22:aa:bb:cc', op='who-has')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone


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
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:00:00:00:00:00', op='who-has')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone


def test_notice_on_response_not_sent_to_unicast(arp):
    e = Ether(src='00:11:22:aa:bb:cd', dst='ff:ff:ff:ff:ff:ff')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:00:00:00:00:00', op='is-at')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone


def test_notice_on_linklayer_address_does_not_match_arps(arp):
    # Request
    e = Ether(src='00:11:22:aa:bb:cd', dst='ff:ff:ff:ff:ff:ff')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:00:00:00:00:00', op='who-has')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone

    # Reply
    e = Ether(src='00:11:22:aa:bb:cd', dst='00:11:22:aa:bb:cc')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:11:22:aa:bb:cd', op='is-at')
    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone


def test_notice_on_double_request(arp):
    """
    RFC826 Deviation. (Not really a deviation, but something might be wrong here)
    Client is not working properly if it does multiple ARP requests for the same IP
    """

    e = Ether(src='00:11:22:aa:bb:ca', dst='ff:ff:ff:ff:ff:ff')
    a = ARP(hwsrc='00:11:22:aa:bb:ca', hwdst='00:00:00:00:00:00', psrc='10.0.0.2', pdst='10.0.0.1', op='who-has')

    response = arp.receive_packet(e / a)
    assert type(response) is PermittedResponse

    response = arp.receive_packet(e / a)
    assert type(response) is NoticeRespone


def test_notice_replier_should_have_saved_request_ip_mac(arp):
    """
    RFC826 Deviation.
    When a client received a request, it should add the ip-mac from this requester, and
    not do a request for this ip later.
    """

    # Sender of this reply should have saved the src MAC and src IP of the request
    e = Ether(src='00:11:22:aa:bb:cd', dst='00:11:22:aa:bb:ca')
    a = ARP(hwsrc='00:11:22:aa:bb:cd', hwdst='00:11:22:aa:bb:ca', psrc='10.0.0.1', pdst='10.0.0.2', op='is-at')
    response = arp.receive_packet(e / a)
    assert type(response) is PermittedResponse

    # Sender of previous reply should not do a new request
    e = Ether(src='00:11:22:aa:bb:cd', dst='ff:ff:ff:ff:ff:ff')
    a = ARP(hwsrc='00:11:22:aa:bb:cd', hwdst='00:00:00:00:00:00', psrc='10.0.0.1', pdst='10.0.0.2', op='who-has')
    arp.receive_packet(e / a)
    response = arp.receive_packet(e / a)

    assert type(response) is NoticeRespone


def test_error_when_ip_not_in_acl():
    from modules.arp.arp_module import ARPModule
    arp = ARPModule(ACL({
        '00:11:22:aa:bb:cc': '10.10.10.2'
    }))

    e = Ether(src='00:11:22:aa:bb:cc', dst='00:11:22:aa:bb:cd')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:11:22:aa:bb:cd', psrc='10.10.10.1', op='is-at')

    response = arp.receive_packet(e / a)
    assert type(response) == ErrorResponse


def test_permitted_when_ip_in_acl():
    from modules.arp.arp_module import ARPModule
    arp = ARPModule(ACL({
        '00:11:22:aa:bb:cc': '10.10.10.2'
    }))

    e = Ether(src='00:11:22:aa:bb:cc', dst='00:11:22:aa:bb:cd')
    a = ARP(hwsrc='00:11:22:aa:bb:cc', hwdst='00:11:22:aa:bb:cd', psrc='10.10.10.2', op='is-at')

    response = arp.receive_packet(e / a)
    assert type(response) == PermittedResponse


def test_acl():
    from modules.arp.arp_module import ACL

    acl = ACL({
        '00:11:22:aa:bb:cd': '10.10.10.2',
        '11:de:fa:ce:d0:11': ['10.10.10.3', '10.10.10.4'],
    })
    assert acl.mac_ip_is_in_acl('00:11:22:aa:bb:cd', '10.10.10.2')
    assert not acl.mac_ip_is_in_acl('00:11:22:aa:bb:cd', '10.10.10.3')
    assert not acl.mac_ip_is_in_acl('00:11:22:aa:bb:ca', '10.10.10.2')

    assert acl.mac_ip_is_in_acl('11:de:fa:ce:d0:11', '10.10.10.3')
    assert acl.mac_ip_is_in_acl('11:de:fa:ce:d0:11', '10.10.10.4')


def test_acl_from_file():
    from modules.arp.arp_module import ACL

    p = Path('temp_test_acl_from_file.txt')
    with p.open(mode='w') as f:
        f.writelines(['10.0.0.1 11:ba:da:a5:55:11\n',
                      '10.0.0.2 11:ba:da:a5:55:11\n',
                      '192.168.178.5 11:8b:ad:f0:0d:11\n',
                      '12.12.12.12 11:de:fa:ce:d0:11\n',
                      '12.12.12.12 11:de:fa:ce:d0:13\n'])

    acl = ACL.from_file(p)

    assert dict(acl.acl) == {
        '10.0.0.1': ['11:ba:da:a5:55:11'],
        '10.0.0.2': ['11:ba:da:a5:55:11'],
        '192.168.178.5': ['11:8b:ad:f0:0d:11'],
        '12.12.12.12': ['11:de:fa:ce:d0:11', '11:de:fa:ce:d0:13']
    }

    p.unlink()
