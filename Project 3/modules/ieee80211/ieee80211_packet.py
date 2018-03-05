import struct
from enum import Enum, unique

from util import parse_mac_field


class RadioTapHeader:
    fields = ['revision', 'pad', 'length']

    def __init__(self, **kwargs) -> None:
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])

        super().__init__()

    @classmethod
    def from_pkt(cls, buffer):
        revision = struct.unpack('<B', bytes([buffer[0]]))[0]
        pad = struct.unpack('<B', bytes([buffer[1]]))[0]
        length = struct.unpack('<H', bytes(buffer[2:4]))[0]
        return cls(revision=revision, pad=pad, length=length)

    def to_json(self):
        return self.__dict__


class IEEE80211Packet:
    fields = ['version', 'type', 'subtype', 'duration', 'dst', 'src', 'bssid', 'seqnr', 'data']

    def __init__(self, **kwargs):
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])

    @classmethod
    def from_pkt(cls, buffer):
        def _parse_frame_control(sub_buffer):

            s_sub_buffer = '{:0>16b}'.format(sub_buffer)

            version = int(s_sub_buffer[6:8], 2)
            m_type = int(s_sub_buffer[4:6], 2)

            # Subtype
            if m_type == 0:
                try:
                    subtype = IEEE80211ManagementFrame(int(s_sub_buffer[:4], 2))
                except ValueError:
                    subtype = IEEE80211ManagementFrame.OTHER
            elif m_type == 1:
                subtype = IEEE80211ControlFrame(int(s_sub_buffer[:4], 2))
            elif m_type == 2:
                subtype = IEEE80211DataFrame(int(s_sub_buffer[:4], 2))
            else:
                subtype = None

            return version, m_type, subtype

        def _parse_seq_nr(sub_buffer):
            fragment_nr = 0
            seq_nr = sub_buffer >> 4
            return fragment_nr, seq_nr

        version, m_type, subtype = _parse_frame_control(struct.unpack('>H', bytes(buffer[:2]))[0])
        duration = struct.unpack('>H', bytes(buffer[2:4]))[0]
        dst = parse_mac_field(buffer[4:10])
        src = parse_mac_field(buffer[10:16])
        bssid = parse_mac_field(buffer[16:22])
        fragment_nr, seq_nr = _parse_seq_nr(struct.unpack('<H', bytes(buffer[22:24]))[0])

        pkt = cls(subtype=subtype, duration=duration, dst=dst, src=src, bssid=bssid, seqnr=seq_nr)

        if isinstance(subtype, IEEE80211DataFrame):
            wep_p = struct.unpack('>L', bytes(buffer[24:28]))[0]
            wep_p = '{:0>32b}'.format(wep_p)
            pkt.wep_iv = int(wep_p[:24], 2)

        return pkt

    def to_json(self):
        return self.__dict__


@unique
class IEEE80211ManagementFrame(Enum):
    ASSOCIATION_REQUEST = 0
    ASSOCIATION_RESPONSE = 1
    REASSOCIATION_REQUEST = 2
    REASSOCIATION_RESPONSE = 3
    BEACON = 8
    PROBE_REQUEST = 4
    DISASSOCIATION = 10
    AUTHENTICATION = 11
    DEAUTHENTICATION = 12
    OTHER = 9999


@unique
class IEEE80211ControlFrame(Enum):
    OTHER = 9999


@unique
class IEEE80211DataFrame(Enum):
    DATA = 0
    OTHER = 9999
