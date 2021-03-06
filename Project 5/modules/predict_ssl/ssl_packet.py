from util import parse_tcp, SIZE_HEADER_ETHERNET, SIZE_HEADER_IPV4

from enum import Enum
import struct

from ips_logger import get_logger

log = get_logger()


class HandshakeTypes(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    NEW_SESSION_TICKET = 4
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_STATUS = 22
    OTHER = 9999


class ContentTypes(Enum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18
    OTHER = 9999


class SSLPacket:
    fields = ['records']

    def __init__(self, records):
        self.records = records

    def __str__(self):
        return 'SSL packet, records: {}'.format([r.__dict__ for r in self.records],)

    @classmethod
    def from_pkt(cls, pkt):
        offset_begin_t = SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4
        tcp_header, tcp_header_size = parse_tcp(pkt)
        ssl_record_offset = offset_begin_t + tcp_header_size

        ssl_records = list()
        while ssl_record_offset < len(pkt):
            record, ssl_record_offset = cls.parse_ssl_record(pkt, ssl_record_offset)

            if not record:
                return cls(records=ssl_records)

            ssl_records.append(record)

        return cls(records=ssl_records)

    @staticmethod
    def parse_ssl_record(pkt, offset):
        try:
            content_type = ContentTypes(struct.unpack('>B', bytes(pkt[offset:offset + 1]))[0])
        except ValueError as e:
            log.debug('Could not parse content_type: {}'.format(e))
            return None, 0

        version = struct.unpack('>H', bytes(pkt[offset + 1:offset + 3]))[0]
        record_length = struct.unpack('>H', bytes(pkt[offset + 3:offset + 5]))[0]

        if content_type == ContentTypes.HANDSHAKE:
            try:
                handshake_type = HandshakeTypes(struct.unpack('>B', bytes(pkt[offset + 5:offset + 6]))[0])
                return SSLHandshakeRecord(content_type=content_type, version=version, record_length=record_length,
                                          handshake_type=handshake_type), offset + record_length + 5
            except ValueError as e:
                log.debug('Could not parse handshake_type: {}'.format(e))
                return None, 0

        return SSLRecord(content_type=content_type, version=version,
                         record_length=record_length), offset + record_length + 5


class SSLRecord:
    fields = ['content_type', 'version', 'record_length']

    def __init__(self, **kwargs):
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])


class SSLHandshakeRecord(SSLRecord):

    def __init__(self, **kwargs):
        SSLRecord.__init__(self, **kwargs)

        self.fields.append('handshake_type')

        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])


def test_parse_client_hello():
    pkt = b'\x30\x5a\x3a\xa4\xd0\x14\xc8\x60\x00\x8a\x7b\xbf\x08\x00\x45\x00' \
          b'\x00\xf1\xd2\xf3\x40\x00\x40\x06\x37\x93\xc0\xa8\xfe\xc8\xd5\xef' \
          b'\x9a\x1f\x92\x6c\x01\xbb\x5b\x1f\xe0\xc1\x1e\x71\xd5\x4a\x80\x18' \
          b'\x00\xe5\x30\x64\x00\x00\x01\x01\x08\x0a\x37\x7f\x0a\xbc\x13\xab' \
          b'\xd6\x50\x16\x03\x01\x00\xb8\x01\x00\x00\xb4\x03\x03\x95\x43\x44' \
          b'\x81\x43\x72\x29\x59\x09\xde\x44\x1d\xa0\x65\xf6\x10\xbd\x2b\xd5' \
          b'\xb5\x84\x9a\x30\xbf\x53\x00\xc9\x85\xdb\x77\x6f\x78\x00\x00\x1e' \
          b'\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\xc0\x0a\xc0\x09' \
          b'\xc0\x13\xc0\x14\x00\x33\x00\x39\x00\x2f\x00\x35\x00\x0a\x01\x00' \
          b'\x00\x6d\x00\x00\x00\x11\x00\x0f\x00\x00\x0c\x74\x77\x65\x61\x6b' \
          b'\x65\x72\x73\x2e\x6e\x65\x74\x00\x17\x00\x00\xff\x01\x00\x01\x00' \
          b'\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b' \
          b'\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c\x02\x68' \
          b'\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00' \
          b'\x00\x00\x00\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08' \
          b'\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'

    parsed = SSLPacket.from_pkt(pkt)

    assert parsed.records[0].content_type == ContentTypes.HANDSHAKE
    assert parsed.records[0].handshake_type == HandshakeTypes.CLIENT_HELLO


def test_parse_server_hello_and_certificate():
    pkt = b'\xc8\x60\x00\x8a\x7b\xbf\x30\x5a\x3a\xa4\xd0\x14\x08\x00\x45\x00' \
          b'\x05\xdc\x03\x1c\x40\x00\x35\x06\x0d\x80\xd5\xef\x9a\x1f\xc0\xa8' \
          b'\xfe\xc8\x01\xbb\x92\x6c\x1e\x71\xd5\x4a\x5b\x1f\xe1\x7e\x80\x10' \
          b'\x00\xeb\x55\x94\x00\x00\x01\x01\x08\x0a\x13\xab\xd6\x51\x37\x7f' \
          b'\x0a\xbc\x16\x03\x03\x00\x6c\x02\x00\x00\x68\x03\x03\x5a\xaa\xbc' \
          b'\x88\xbb\x31\xcf\xd8\x4f\x7f\xb2\x0f\x71\x22\xbf\x67\xdf\x54\x7d' \
          b'\x10\x57\x41\xab\xfd\x6a\x5c\x7b\x71\x08\xa7\xba\x4a\x20\x7f\xba' \
          b'\xae\xf6\x88\x65\x7f\x16\xea\xd7\xc7\x10\xc0\x40\xd9\xd3\x46\xab' \
          b'\x48\x00\x8c\xd8\x51\x0e\x97\x96\x93\xbc\x0c\xa4\x40\xc9\xc0\x2b' \
          b'\x00\x00\x20\x00\x00\x00\x00\x00\x05\x00\x00\xff\x01\x00\x01\x00' \
          b'\x00\x10\x00\x05\x00\x03\x02\x68\x32\x00\x0b\x00\x02\x01\x00\x00' \
          b'\x23\x00\x00\x16\x03\x03\x0a\x20\x0b\x00\x0a\x1c\x00\x0a\x19\x00' \
          b'\x05\x7d\x30\x82\x05\x79\x30\x82\x04\x61\xa0\x03\x02\x01\x02\x02' \
          b'\x12\x03\x04\xe4\x40\xaf\x47\x9c\xb9\xc2\x01\x98\x1a\xac\x88\x0f' \
          b'\x59\xe9\xf1\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b' \
          b'\x05\x00\x30\x4a\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55' \
          b'\x53\x31\x16\x30\x14\x06\x03\x55\x04\x0a\x13\x0d\x4c\x65\x74\x27' \
          b'\x73\x20\x45\x6e\x63\x72\x79\x70\x74\x31\x23\x30\x21\x06\x03\x55' \
          b'\x04\x03\x13\x1a\x4c\x65\x74\x27\x73\x20\x45\x6e\x63\x72\x79\x70' \
          b'\x74\x20\x41\x75\x74\x68\x6f\x72\x69\x74\x79\x20\x58\x33\x30\x1e' \
          b'\x17\x0d\x31\x38\x30\x33\x30\x38\x31\x32\x31\x34\x32\x36\x5a\x17' \
          b'\x0d\x31\x38\x30\x36\x30\x36\x31\x32\x31\x34\x32\x36\x5a\x30\x17' \
          b'\x31\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x74\x77\x65\x61\x6b' \
          b'\x65\x72\x73\x2e\x6e\x65\x74\x30\x59\x30\x13\x06\x07\x2a\x86\x48' \
          b'\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42' \
          b'\x00\x04\x3e\x9c\x93\xbf\x45\x3c\xa3\xf3\x6b\x90\x96\x8f\xb8\x6a' \
          b'\x93\xbb\x34\xe7\x96\xd9\xbd\x22\xea\xa0\xe2\xb8\x8e\xcb\x20\xfe' \
          b'\x7f\x25\x63\x7b\xa4\xcf\xbb\x0d\x47\x7e\x19\x7f\x2d\xab\x27\x94' \
          b'\x0b\xef\x90\xef\x2e\x2e\x35\x48\x5a\x5e\xe5\xd0\x59\xc7\x71\xbf' \
          b'\xcb\x0e\xa3\x82\x03\x55\x30\x82\x03\x51\x30\x0e\x06\x03\x55\x1d' \
          b'\x0f\x01\x01\xff\x04\x04\x03\x02\x07\x80\x30\x1d\x06\x03\x55\x1d' \
          b'\x25\x04\x16\x30\x14\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x06' \
          b'\x08\x2b\x06\x01\x05\x05\x07\x03\x02\x30\x0c\x06\x03\x55\x1d\x13' \
          b'\x01\x01\xff\x04\x02\x30\x00\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16' \
          b'\x04\x14\x80\x4e\x4d\xed\x8a\x1f\xe3\x6b\x63\xb7\x5f\x55\x4f\xc9' \
          b'\xa5\xe9\x86\xf2\xf9\x96\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30' \
          b'\x16\x80\x14\xa8\x4a\x6a\x63\x04\x7d\xdd\xba\xe6\xd1\x39\xb7\xa6' \
          b'\x45\x65\xef\xf3\xa8\xec\xa1\x30\x6f\x06\x08\x2b\x06\x01\x05\x05' \
          b'\x07\x01\x01\x04\x63\x30\x61\x30\x2e\x06\x08\x2b\x06\x01\x05\x05' \
          b'\x07\x30\x01\x86\x22\x68\x74\x74\x70\x3a\x2f\x2f\x6f\x63\x73\x70' \
          b'\x2e\x69\x6e\x74\x2d\x78\x33\x2e\x6c\x65\x74\x73\x65\x6e\x63\x72' \
          b'\x79\x70\x74\x2e\x6f\x72\x67\x30\x2f\x06\x08\x2b\x06\x01\x05\x05' \
          b'\x07\x30\x02\x86\x23\x68\x74\x74\x70\x3a\x2f\x2f\x63\x65\x72\x74' \
          b'\x2e\x69\x6e\x74\x2d\x78\x33\x2e\x6c\x65\x74\x73\x65\x6e\x63\x72' \
          b'\x79\x70\x74\x2e\x6f\x72\x67\x2f\x30\x82\x01\x5e\x06\x03\x55\x1d' \
          b'\x11\x04\x82\x01\x55\x30\x82\x01\x51\x82\x15\x63\x68\x61\x72\x74' \
          b'\x73\x2e\x74\x77\x65\x61\x6b\x7a\x6f\x6e\x65\x73\x2e\x6e\x65\x74' \
          b'\x82\x10\x66\x61\x71\x2e\x74\x77\x65\x61\x6b\x65\x72\x73\x2e\x6e' \
          b'\x65\x74\x82\x16\x67\x61\x74\x68\x65\x72\x69\x6e\x67\x2e\x74\x77' \
          b'\x65\x61\x6b\x65\x72\x73\x2e\x6e\x65\x74\x82\x0f\x69\x63\x2e\x74' \
          b'\x77\x65\x61\x6b\x69\x6d\x67\x2e\x6e\x65\x74\x82\x10\x69\x6d\x73' \
          b'\x2e\x74\x77\x65\x61\x6b\x65\x72\x73\x2e\x6e\x65\x74\x82\x17\x70' \
          b'\x72\x69\x63\x65\x77\x61\x74\x63\x68\x2e\x74\x77\x65\x61\x6b\x65' \
          b'\x72\x73\x2e\x6e\x65\x74\x82\x13\x73\x65\x63\x75\x72\x65\x2e\x74' \
          b'\x77\x65\x61\x6b\x65\x72\x73\x2e\x6e\x65\x74\x82\x13\x73\x74\x61' \
          b'\x74\x69\x63\x2e\x74\x77\x65\x61\x6b\x65\x72\x73\x2e\x6e\x65\x74' \
          b'\x82\x0b\x74\x77\x65\x61\x6b\x65\x72\x73\x2e\x62\x65\x82\x0d\x74' \
          b'\x77\x65\x61\x6b\x65\x72\x73\x2e\x6d\x6f\x62\x69\x82\x0c\x74\x77' \
          b'\x65\x61\x6b\x65\x72\x73\x2e\x6e\x65\x74\x82\x0b\x74\x77\x65\x61' \
          b'\x6b\x65\x72\x73\x2e\x6e\x6c\x82\x0b\x74\x77\x65\x61\x6b\x65\x72' \
          b'\x73\x2e\x74\x76\x82\x0c\x74\x77\x65\x61\x6b\x69\x6d\x67\x2e\x6e' \
          b'\x65\x74\x82\x06\x74\x77\x6b\x2e\x72\x73\x82\x1a\x77\x77\x77\x2e' \
          b'\x67\x61\x74\x68\x65\x72\x69\x6e\x67\x2e\x74\x77\x65\x61\x6b\x65' \
          b'\x72\x73\x2e\x6e\x65\x74\x82\x0f\x77\x77\x77\x2e\x74\x77\x65\x61' \
          b'\x6b\x65\x72\x73\x2e\x62\x65\x82\x10\x77\x77\x77\x2e\x74\x77\x65' \
          b'\x61\x6b\x65\x72\x73\x2e\x6e\x65\x74\x82\x0f\x77\x77\x77\x2e\x74' \
          b'\x77\x65\x61\x6b\x65\x72\x73\x2e\x6e\x6c\x30\x81\xfe\x06\x03\x55' \
          b'\x1d\x20\x04\x81\xf6\x30\x81\xf3\x30\x08\x06\x06\x67\x81\x0c\x01' \
          b'\x02\x01\x30\x81\xe6\x06\x0b\x2b\x06\x01\x04\x01\x82\xdf\x13\x01' \
          b'\x01\x01\x30\x81\xd6\x30\x26\x06\x08\x2b\x06\x01\x05\x05\x07\x02' \
          b'\x01\x16\x1a\x68\x74\x74\x70\x3a\x2f\x2f\x63\x70\x73\x2e\x6c\x65' \
          b'\x74\x73\x65\x6e\x63\x72\x79\x70\x74\x2e\x6f\x72\x67\x30\x81\xab' \
          b'\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x02\x30\x81\x9e\x0c\x81\x9b' \
          b'\x54\x68\x69\x73\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65' \
          b'\x20\x6d\x61\x79\x20\x6f\x6e\x6c\x79\x20\x62\x65\x20\x72\x65\x6c' \
          b'\x69\x65\x64\x20\x75\x70\x6f\x6e\x20\x62\x79\x20\x52\x65\x6c\x79' \
          b'\x69\x6e\x67\x20\x50\x61\x72\x74\x69\x65\x73\x20\x61\x6e\x64\x20' \
          b'\x6f\x6e\x6c\x79\x20\x69\x6e\x20\x61\x63\x63\x6f\x72\x64\x61\x6e' \
          b'\x63\x65\x20\x77\x69\x74\x68\x20\x74\x68\x65\x20\x43\x65\x72\x74' \
          b'\x69\x66\x69\x63\x61\x74\x65\x20\x50\x6f\x6c\x69\x63\x79\x20\x66' \
          b'\x6f\x75\x6e\x64\x20\x61\x74\x20\x68\x74\x74\x70\x73\x3a\x2f\x2f' \
          b'\x6c\x65\x74\x73\x65\x6e\x63\x72\x79\x70\x74\x2e\x6f\x72\x67\x2f' \
          b'\x72\x65\x70\x6f\x73\x69\x74\x6f\x72\x79\x2f\x30\x0d\x06\x09\x2a' \
          b'\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x69' \
          b'\x24\xf2\x2d\xf6\xc3\x43\xed\xb7\x2a\xcd\x08\xf0\x10\xb1\xcd\xb0' \
          b'\x86\xc1\xc2\x00\xf3\xbd\x5d\x99\x74\x9b\xde\xb2\x36\x80\x17\x6c' \
          b'\xc4\xf1\x87\xb6\x8e\xcc\x03\xda\x03\xd5\x80\xfc\xf2\xd0\xb2\x0a' \
          b'\x72\x61\x05\x8f\x25\x2f\x8c\x9c\xb8\xd2\xd0\x78\xa8\xe2\x2f\xa3' \
          b'\x9f\x78\x54\xf3\x24\x9b\x54\xa3\x92\x1d\xbf\x8d\x67\x76\xdb\x1b' \
          b'\x2b\x8f\x59\xa8\xda\xed\xb3\x99\x61\x41\x24\xeb\xe6\x7a\xc4\x10' \
          b'\x59\x17\x4b\xa8\x43\x9c\xcf\xae\xb0\x70\xba\xfd\x42\x05\x50\xec' \
          b'\xc7\x3c\x29\x3a\x66\x61\xa9\xc4\x57\xe3\x48\x31\x8e\x11\x89\xc4' \
          b'\x71\x6e\x6d\xd3\x20\x06\x53\x60\x78\xf6\xde\xbb\x65\x49\x15\xd3' \
          b'\x77\x1d\x27\x51\xc5\xaa\xbb\x3f\xb2\x1c\x8c\x21\xa7\x3b\x69\xe5' \
          b'\x2a\xbd\xd4\x61\x29\x66\x15\x4a\xbe\x3b'

    parsed = SSLPacket.from_pkt(pkt)

    assert parsed.records[0].content_type == ContentTypes.HANDSHAKE
    assert parsed.records[0].handshake_type == HandshakeTypes.SERVER_HELLO

    assert parsed.records[1].content_type == ContentTypes.HANDSHAKE
    assert parsed.records[1].handshake_type == HandshakeTypes.CERTIFICATE


def test_parse_application_data():
    pkt = b'\xc8\x60\x00\x8a\x7b\xbf\x30\x5a\x3a\xa4\xd0\x14\x08\x00\x45\x00' \
          b'\x00\x87\x03\x21\x40\x00\x35\x06\x12\xd0\xd5\xef\x9a\x1f\xc0\xa8' \
          b'\xfe\xc8\x01\xbb\x92\x6c\x1e\x71\xe3\x91\x5b\x1f\xe3\x9c\x80\x18' \
          b'\x00\xfc\x69\xc6\x00\x00\x01\x01\x08\x0a\x13\xab\xd6\x53\x37\x7f' \
          b'\x0a\xc3\x17\x03\x03\x00\x4e\x86\x86\x5b\x9c\x4a\x12\x95\x7e\x12' \
          b'\xe3\x30\xf0\x0a\xcf\xde\xc6\xbc\x9b\x0a\x51\x29\x71\x7e\x9c\xda' \
          b'\x47\x83\x7d\x6f\x55\x1f\x66\xf2\x14\x26\xb2\x80\xd8\xf0\xa0\xd6' \
          b'\x82\xb9\xff\xd7\x47\xdb\x93\xcf\x56\xfd\xae\x1f\x75\xe7\x8c\x49' \
          b'\x6d\x1b\x0d\x94\xf6\xa3\x1c\x26\x63\x1b\xac\xde\x72\xc1\x4f\xc7' \
          b'\xef\x80\x53\x41\x91'

    parsed = SSLPacket.from_pkt(pkt)

    assert parsed.records[0].content_type == ContentTypes.APPLICATION_DATA


if __name__ == '__main__':
    test_parse_application_data()
