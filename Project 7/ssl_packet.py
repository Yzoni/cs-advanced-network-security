from enum import Enum
import struct


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


class Extensions(Enum):  # INCOMPLETE
    SERVER_NAME = 0
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    EC_POINT_FORMATS = 11
    SIGNATURE_ALGORITHMS = 13
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    EXTENDED_MASTER_SECRET = 23
    SESSION_TICKET_TLS = 35
    SUPPORTED_VERSIONS = 43
    PSK_KEY_EXCHANGE_MODES = 45
    KEY_SHARE = 51
    RENEGOTIATION_INFO = 65281
    OTHER = 999999


class SSLPacket:
    fields = ['records']

    def __init__(self, records):
        self.records = records

    def __str__(self):
        return 'SSL packet, records: {}'.format([r.__dict__ for r in self.records], )

    @classmethod
    def from_pkt(cls, pkt):
        ssl_records = list()
        ssl_record_offset = 0
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
            print('Could not parse content_type: {}'.format(e))
            return None, 0

        version = struct.unpack('>H', bytes(pkt[offset + 1:offset + 3]))[0]
        record_length = struct.unpack('>H', bytes(pkt[offset + 3:offset + 5]))[0]

        offset += 5

        if content_type == ContentTypes.HANDSHAKE:
            try:
                handshake_type = HandshakeTypes(struct.unpack('>B', bytes(pkt[offset]))[0])
                handshake_length = record_length - 4

                offset += 4

                if handshake_type.CLIENT_HELLO:
                    return SSLHandshakeClientHelloRecord.from_pkt(pkt[offset:], content_type=content_type,
                                                                  version=version,
                                                                  record_length=record_length,
                                                                  handshake_type=handshake_type,
                                                                  handshake_length=handshake_length), offset + record_length

                return SSLHandshakeRecord(content_type=content_type, version=version, record_length=record_length,
                                          handshake_type=handshake_type,
                                          handshake_length=handshake_length), offset + record_length
            except ValueError as e:
                print('Could not parse handshake_type: {}'.format(e))
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
    handshake_fields = ['handshake_type', 'length']

    def __init__(self, **kwargs):
        SSLRecord.__init__(self, **kwargs)

        self.fields += self.handshake_fields

        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])


class SSLHandshakeClientHelloRecord(SSLHandshakeRecord):
    client_hello_fields = ['handshake_version', 'random', 'session_id_length', 'session_id', 'session_id',
                           'cipher_suites_length',
                           'cipher_suites', 'compression_methods_length', 'compression_methods', 'extensions_length',
                           'extensions']

    def __init__(self, **kwargs):
        SSLHandshakeRecord.__init__(self, **kwargs)

        self.fields += self.client_hello_fields

        self._set_kwargs(kwargs)

    def _set_kwargs(self, kwargs):
        for key in self.fields:
            if key in kwargs:
                setattr(self, key, kwargs[key])

    @classmethod
    def from_pkt(cls, p_pkt, **kwargs):
        """

        :param p_pkt: Partial packet, starting from beginning of "version"
        :param kwargs:
        :return:
        """

        version = struct.unpack('>H', bytes(p_pkt[:2]))[0]

        random = bytes(p_pkt[2:34])
        session_id_length = struct.unpack('>B', bytes([p_pkt[34]]))[0]
        session_id = bytes(p_pkt[35:35 + session_id_length])

        offset = 35 + session_id_length

        cipher_suite_length = struct.unpack('>H', bytes(p_pkt[offset:offset + 2]))[0]
        cipher_suites = bytes(p_pkt[offset + 2:offset + 2 + cipher_suite_length])

        offset += 2 + cipher_suite_length

        compression_methods_length = struct.unpack('>B', bytes([p_pkt[offset]]))[0]
        compression_methods = bytes(p_pkt[offset: offset + compression_methods_length])

        offset += 1 + compression_methods_length

        extension_length = struct.unpack('>H', bytes(p_pkt[offset:offset + 2]))[0]

        offset += 2

        extensions = list()
        while offset < kwargs['handshake_length']:
            ext = SSLExtension.from_pkt(p_pkt[offset:])
            extensions.append(ext)
            offset += ext.length + 4

        return cls(handshake_version=version, random=random, session_id_length=session_id_length, session_id=session_id,
                   cipher_suite_length=cipher_suite_length, cipher_suites=cipher_suites,
                   compression_methods_length=compression_methods_length, compression_methods=compression_methods,
                   extension_length=extension_length, extensions=extensions, **kwargs)


class SSLExtension:

    def __init__(self, type, length, data):
        self.type = type
        self.length = length
        self.data = data

    def __repr__(self):
        return str(self.__dict__)

    @classmethod
    def from_pkt(cls, p_pkt):
        """
        :param p_pkt: Partial packet, starting from first extension
        :return: SSLExtension
        """
        try:
            type = Extensions(struct.unpack('>H', bytes(p_pkt[:2]))[0])
        except ValueError as e:
            type = Extensions.OTHER

        length = struct.unpack('>H', bytes(p_pkt[2:4]))[0]

        if type == Extensions.SERVER_NAME:
            data = SSLExtensionServerName.from_pkt(p_pkt[4:4 + length])
        else:
            data = p_pkt[4:4 + length]

        return cls(type=type, length=length, data=data)


class SSLExtensionServerName:

    def __init__(self, list_length, type, name_length, name) -> None:
        super().__init__()

        self.list_length = list_length
        self.type = type
        self.name_length = name_length
        self.name = name

    def __repr__(self):
        return str(self.__dict__)

    @classmethod
    def from_pkt(cls, p_pkt):
        list_length = struct.unpack('>H', bytes(p_pkt[:2]))[0]
        type = struct.unpack('>B', bytes([p_pkt[2]]))[0]
        name_length = struct.unpack('>H', bytes(p_pkt[3:5]))[0]
        name = p_pkt[5:].decode()
        return cls(list_length=list_length, type=type, name_length=name_length, name=name)


def test_client_hello_parse():
    pkt = b"\x16\x03\x01\x02\x07\x01\x00\x02\x03\x03\x03\xfb\x4e\xbd\x90\x20" \
          b"\x16\xfe\xf9\x33\x3e\xde\xb9\x78\x68\xc2\xab\x99\xac\x6e\x13\xde" \
          b"\xf9\x8e\x8e\xe1\xa7\x97\xc7\x23\xe2\x35\xcd\x20\xe8\x12\x3b\x13" \
          b"\xd5\x98\x0d\xd3\x50\x4a\x3f\x87\xb8\xa8\x88\x09\x5c\xb1\xae\xb0" \
          b"\x3c\xf7\xe3\xcc\x90\x81\x1c\xa1\xf7\xf9\x87\xf7\x00\x1c\x13\x01" \
          b"\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30" \
          b"\xc0\x13\xc0\x14\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x9e\x00\x00" \
          b"\x00\x0c\x00\x0a\x00\x00\x07\x79\x72\x63\x6b\x2e\x6e\x6c\x00\x17" \
          b"\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0e\x00\x0c\x00\x1d\x00" \
          b"\x17\x00\x18\x00\x19\x01\x00\x01\x01\x00\x0b\x00\x02\x01\x00\x00" \
          b"\x23\x00\xb0\xe8\x75\xe2\x36\x13\x08\xb4\xc6\x9f\xdf\x38\x58\x0a" \
          b"\xc2\x2a\x36\xd8\x31\x78\x88\xc3\x80\x6e\x33\x73\xb5\x0a\x68\xf9" \
          b"\xe9\x05\x42\x3e\x55\xe6\x4d\x17\xdd\x76\x6c\x15\xb8\x10\x76\xab" \
          b"\x42\x17\x19\xcc\x18\xf8\xcc\x2d\xe1\xcf\x57\x3a\x18\x65\xc2\x09" \
          b"\x35\xf8\xa4\xf6\x56\x5a\x72\xc8\xae\x09\xe0\xe6\xb3\xa2\x2d\x22" \
          b"\xbb\xcb\x81\xfb\x2c\x23\xe4\x5c\xa0\xd2\xd9\xe5\x14\x89\xec\xc7" \
          b"\xdd\xca\x45\x41\xed\x3c\xaa\xb4\xa9\xc4\x58\x76\x88\xac\x94\xef" \
          b"\x6b\xe2\x37\xfc\x76\x28\x5b\xe6\x96\xde\x3b\x11\x6b\x24\xe7\x2d" \
          b"\xd3\x54\x2c\x4e\xa4\x34\xa8\xf5\xae\x65\xad\x39\x89\xc3\xdf\x5e" \
          b"\x67\x0b\xf0\xcb\xa2\x22\x31\xb9\xad\x34\x6a\xda\x82\x71\xea\x64" \
          b"\xe8\xa4\x11\x70\x43\x14\xc1\x2f\x55\x54\x08\x62\xef\xef\x1c\x02" \
          b"\x5b\x7b\x0b\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74" \
          b"\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x33" \
          b"\x00\x6b\x00\x69\x00\x1d\x00\x20\xd1\x7d\x1b\x2a\x9c\xb6\x4d\xc9" \
          b"\xde\x17\x0a\xaa\x67\x54\x34\xa0\x7a\x34\x24\x87\xeb\x26\x3e\x38" \
          b"\x6b\xda\x71\x18\x20\x28\x3a\x22\x00\x17\x00\x41\x04\xc8\x24\x52" \
          b"\x20\x73\xb9\xb4\x28\xdd\x9a\x61\x80\xce\xc4\x9c\xf4\x0c\x4c\xcf" \
          b"\x35\xe9\x8b\xc3\x07\x3a\xab\x42\x0f\xd8\xdb\x1b\x36\x14\x10\x02" \
          b"\x7e\xb6\xf6\x8a\xd9\x6c\x1f\x44\x4f\xa8\x1c\xb7\x80\x56\x1b\x0d" \
          b"\x71\xfb\x14\x08\xee\x12\xfa\x98\xdb\x7f\xfd\xe3\xb8\x00\x2b\x00" \
          b"\x09\x08\x7f\x17\x03\x03\x03\x02\x03\x01\x00\x0d\x00\x18\x00\x16" \
          b"\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01" \
          b"\x06\x01\x02\x03\x02\x01\x00\x2d\x00\x02\x01\x01"

    parsed_pkt = SSLPacket.from_pkt(pkt)

    assert parsed_pkt == type(SSLHandshakeClientHelloRecord)

    print(parsed_pkt)
