import pytest

from ips_response import ErrorResponse
from modules.ieee80211.ieee80211_packet import IEEE80211Packet, RadioTapHeader, IEEE80211DataFrame, \
    IEEE80211ManagementFrame
from modules.ieee80211.ieee80211_module import IEEE80211Module


@pytest.fixture
def wep_arp_broadcast():
    return b'\x08\x41\x00\x00\x00\x25\x9c\xd5\x69\xe1\x00\x00\x00\xb5\x39\x7b' \
           b'\xff\xff\xff\xff\xff\xff\x80\x39\xda\x86\xf0\x00'


@pytest.fixture
def deauth_ieee80211():
    return b'\xc0\x00\x3a\x01\x00\x00\x00\xb5\x39\x7b\x00\x25\x9c\xd5\x69\xe1' \
           b'\x00\x25\x9c\xd5\x69\xe1\x60\x98'


def test_parse_ieee80211_data_frame(wep_arp_broadcast):
    header = IEEE80211Packet.from_pkt(wep_arp_broadcast)
    assert type(header.subtype) == IEEE80211DataFrame
    assert header.wep_iv == 0x00da86f0


def test_error_wep_iv_threshold(wep_arp_broadcast):
    ieee_module = IEEE80211Module(iv_threshold=1)
    ieee_module.receive_packet(wep_arp_broadcast)
    response = ieee_module.receive_packet(wep_arp_broadcast)
    assert type(response) == ErrorResponse


def test_parse_radiotap_header():
    pkt = b'\x00\x00\x08\x00\x00\x00\x00\x00'
    header = RadioTapHeader.from_pkt(pkt)

    assert header.length == 8


def test_parse_ieee80211packet(deauth_ieee80211):
    header = IEEE80211Packet.from_pkt(deauth_ieee80211)

    assert type(header.subtype) == IEEE80211ManagementFrame
    assert header.subtype.value == 12
    assert header.src == '00:25:9c:d5:69:e1'
    assert header.dst == '00:00:00:b5:39:7b'
    assert header.bssid == '00:25:9c:d5:69:e1'
    assert header.seqnr == 2438
