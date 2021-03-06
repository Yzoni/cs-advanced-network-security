import pytest

from ips_response import ErrorResponse
from modules.ieee80211.ieee80211_packet import IEEE80211FrameControl, RadioTapHeader, IEEE80211DataFrameType, \
    IEEE80211ManagementFrameType, IEEE80211DataFrame, IEEE80211ManagementFrameDisAuth, DSBits
from modules.ieee80211.ieee80211_module import IEEE80211Module


@pytest.fixture
def wep_arp_broadcast():
    return b'\x08\x41\x00\x00\x00\x25\x9c\xd5\x69\xe1\x00\x00\x00\xb5\x39\x7b' \
           b'\xff\xff\xff\xff\xff\xff\x10\x05\xda\x86\xf0\x00'


@pytest.fixture
def deauth_ieee80211():
    return b'\xc0\x00\x00\x00\xc0\xbd\xd1\xf1\x17\x90\x00\x25\x9c\xd5\x69\xe1' \
           b'\x00\x25\x9c\xd5\x69\xe1\x00\x00\x03\x00'


@pytest.fixture
def disass_ieee80211():
    return b'\xa0\x00\x00\x00\xc0\xbd\xd1\xf1\x17\x90\x00\x25\x9c\xd5\x69\xe1' \
           b'\x00\x25\x9c\xd5\x69\xe1\x00\x00\x08\x00'


@pytest.fixture
def data_wep_wds_ieee80211():
    return b'\x08\x43\x3a\x01\x50\x0f\x80\xfd\x85\x00\x00\x25\x9c\xd5\x69\xe1' \
           b'\xff\xff\xff\xff\xff\xff\xc0\x2d\x00\x25\x9c\xd5\x69\xdf\xb0\x86\xf0\x00'


def test_parse_radiotap_header():
    pkt = b'\x00\x00\x08\x00\x00\x00\x00\x00'
    header = RadioTapHeader.from_pkt(pkt)

    assert header.length == 8


def test_parse_ieee80211_frame_control_flags(data_wep_wds_ieee80211):
    header = IEEE80211FrameControl.from_pkt(data_wep_wds_ieee80211)
    assert header.order_flag == False
    assert header.protected_flag == True
    assert header.more_data_flag == False
    assert header.pwr_flag == False
    assert header.retry_flag == False
    assert header.more_fragments_flag == False
    assert header.ds_flag == DSBits.WDS


def test_parse_ieee80211_data_frame_data_wds(data_wep_wds_ieee80211):
    frame_control = IEEE80211FrameControl.from_pkt(data_wep_wds_ieee80211)
    data_frame = IEEE80211DataFrame.from_pkt(data_wep_wds_ieee80211, frame_control)
    assert type(frame_control.subtype) == IEEE80211DataFrameType
    assert frame_control.subtype == IEEE80211DataFrameType.DATA

    assert data_frame.address1 == '50:0f:80:fd:85:00'
    assert data_frame.address2 == '00:25:9c:d5:69:e1'
    assert data_frame.address3 == 'ff:ff:ff:ff:ff:ff'
    assert data_frame.seqnr == 732
    assert data_frame.address4 == '00:25:9c:d5:69:df'
    assert data_frame.wep_iv == '0xb086f0'


def test_parse_ieee80211_management_frame_deauth(deauth_ieee80211):
    frame_control = IEEE80211FrameControl.from_pkt(deauth_ieee80211)
    management_frame = IEEE80211ManagementFrameDisAuth.from_pkt(deauth_ieee80211, frame_control)

    assert type(frame_control.subtype) == IEEE80211ManagementFrameType
    assert frame_control.subtype == IEEE80211ManagementFrameType.DEAUTHENTICATION

    assert management_frame.da == 'c0:bd:d1:f1:17:90'
    assert management_frame.sa == '00:25:9c:d5:69:e1'
    assert management_frame.bssid == '00:25:9c:d5:69:e1'
    assert management_frame.reason == 0x0003


def test_parse_ieee80211_management_frame_disass(disass_ieee80211):
    frame_control = IEEE80211FrameControl.from_pkt(disass_ieee80211)
    management_frame = IEEE80211ManagementFrameDisAuth.from_pkt(disass_ieee80211, frame_control)

    assert type(frame_control.subtype) == IEEE80211ManagementFrameType
    assert frame_control.subtype == IEEE80211ManagementFrameType.DISASSOCIATION

    assert management_frame.da == 'c0:bd:d1:f1:17:90'
    assert management_frame.sa == '00:25:9c:d5:69:e1'
    assert management_frame.bssid == '00:25:9c:d5:69:e1'
    assert management_frame.reason == 0x0008


def test_error_wep_iv_threshold(wep_arp_broadcast):
    ieee_module = IEEE80211Module(iv_threshold=1)
    ieee_module.receive_packet(wep_arp_broadcast, 1)
    response = ieee_module.receive_packet(wep_arp_broadcast, 2)
    assert type(response) == ErrorResponse
