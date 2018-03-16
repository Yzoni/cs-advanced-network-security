import struct
from enum import Enum, unique

from util import parse_mac_field
from util import bit_enabled


class RadioTapHeader:
    fields = ['revision', 'pad', 'length']

    def __init__(self, **kwargs):
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])


    @classmethod
    def from_pkt(cls, buffer):
        revision = struct.unpack('<B', bytes([buffer[0]]))[0]
        pad = struct.unpack('<B', bytes([buffer[1]]))[0]
        length = struct.unpack('<H', bytes(buffer[2:4]))[0]
        return cls(revision=revision, pad=pad, length=length)


class IEEE80211FrameControl:
    fields = ['version', 'm_type', 'subtype', 'duration', 'order_flag', 'protected_flag', 'more_data_flag', 'pwr_flag',
              'retry_flag', 'more_fragments_flag', 'ds_flag']

    def __init__(self, **kwargs):
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])

    @classmethod
    def from_pkt(cls, buffer):
        def _parse_frame_control(sub_buffer):

            s_sub_buffer = '{:0>8b}'.format(sub_buffer)

            version = int(s_sub_buffer[6:8], 2)
            m_type = int(s_sub_buffer[4:6], 2)

            # Subtype
            if m_type == 0:
                try:
                    subtype = IEEE80211ManagementFrameType(int(s_sub_buffer[:4], 2))
                except ValueError:
                    subtype = IEEE80211ManagementFrameType.OTHER
            elif m_type == 1:
                try:
                    subtype = IEEE80211ControlFrameType(int(s_sub_buffer[:4], 2))
                except ValueError:
                    subtype = IEEE80211ControlFrameType.OTHER
            elif m_type == 2:
                try:
                    subtype = IEEE80211DataFrameType(int(s_sub_buffer[:4], 2))
                except ValueError:
                    subtype = IEEE80211DataFrameType.OTHER
            else:
                subtype = None

            return version, m_type, subtype

        def _parse_flags(sub_buffer):
            order_flag = bit_enabled(sub_buffer, 7)
            protected_flag = bit_enabled(sub_buffer, 6)
            more_data_flag = bit_enabled(sub_buffer, 5)
            pwr_flag = bit_enabled(sub_buffer, 4)
            retry_flag = bit_enabled(sub_buffer, 3)
            more_fragments_flag = bit_enabled(sub_buffer, 2)
            ds_flag = DSBits(int('{:0>8b}'.format(sub_buffer)[6:8], 2))

            return order_flag, protected_flag, more_data_flag, pwr_flag, retry_flag, more_fragments_flag, ds_flag

        version, m_type, subtype = _parse_frame_control(struct.unpack('>B', bytes([buffer[0]]))[0])
        order_flag, protected_flag, more_data_flag, pwr_flag, retry_flag, more_fragments_flag, ds_flag = _parse_flags(
            struct.unpack('>B', bytes([buffer[1]]))[0])
        duration = struct.unpack('<H', bytes(buffer[2:4]))[0]

        pkt = cls(m_type=m_type, subtype=subtype, duration=duration, order_flag=order_flag,
                  protected_flag=protected_flag, more_data_flag=more_data_flag, pwr_flag=pwr_flag,
                  retry_flag=retry_flag, more_fragments_flag=more_fragments_flag, ds_flag=ds_flag)

        return pkt


class IEEE80211ManagementFrameDisAuth:
    fields = ['da', 'sa', 'bssid', 'seqctl', 'reason']

    def __init__(self, **kwargs):
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])

    @classmethod
    def from_pkt(cls, buffer, frame_control):

        def _parse_seq_nr(sub_buffer):
            fragment_nr = 0
            seq_nr = sub_buffer >> 4
            return fragment_nr, seq_nr

        da = parse_mac_field(buffer[4:10])
        sa = parse_mac_field(buffer[10:16])
        bssid = parse_mac_field(buffer[16:22])
        fragment_nr, seqnr = _parse_seq_nr(struct.unpack('<H', bytes(buffer[22:24]))[0])
        reason = struct.unpack('<H', bytes(buffer[24:26]))[0]

        return cls(da=da, sa=sa, bssid=bssid, fragment_nr=fragment_nr, seqnr=seqnr, reason=reason)


class IEEE80211DataFrame:
    fields = ['address1', 'address2', 'address3', 'address4', 'seqnr', 'wep_iv']

    def __init__(self, **kwargs):
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])

    @classmethod
    def from_pkt(cls, buffer, frame_control):
        def _parse_seq_nr(sub_buffer):
            fragment_nr = 0
            seq_nr = sub_buffer >> 4
            return fragment_nr, seq_nr

        address1 = parse_mac_field(buffer[4:10])
        address2 = parse_mac_field(buffer[10:16])
        address3 = parse_mac_field(buffer[16:22])

        fragment_nr, seqnr = _parse_seq_nr(struct.unpack('<H', bytes(buffer[22:24]))[0])

        if frame_control.ds_flag == DSBits.WDS:
            address4 = parse_mac_field(buffer[24:30])
            wep_p = struct.unpack('>L', bytes(buffer[30:34]))[0]
        else:
            address4 = None
            wep_p = struct.unpack('>L', bytes(buffer[24:28]))[0]

        wep_p = '{:0>32b}'.format(wep_p)
        wep_iv = hex(int(wep_p[:24], 2))

        return cls(address1=address1, address2=address2, address3=address3, address4=address4, seqnr=seqnr,
                   wep_iv=wep_iv)


@unique
class DSBits(Enum):
    IBSS = 0
    TO_AP = 1
    FROM_AP = 2
    WDS = 3


@unique
class IEEE80211ManagementFrameType(Enum):
    ASSOCIATION_REQUEST = 0
    ASSOCIATION_RESPONSE = 1
    REASSOCIATION_REQUEST = 2
    REASSOCIATION_RESPONSE = 3
    BEACON = 8
    PROBE_REQUEST = 4
    DISASSOCIATION = 10
    AUTHENTICATION = 11
    DEAUTHENTICATION = 12
    ACTION = 13
    OTHER = 9999


@unique
class IEEE80211ControlFrameType(Enum):
    RTS = 11
    CTS = 12
    ACK = 13
    OTHER = 9999


@unique
class IEEE80211DataFrameType(Enum):
    DATA = 0
    DATA_CF_ACK = 1
    DATA_CF_POLL = 2
    DATA_CF_ACK_POL = 3
    DATA_NULL = 4
    CF_ACK = 5
    CF_POLL = 6
    CF_ACK_POLL = 7
    CF_QOS = 8
    OTHER = 9999
