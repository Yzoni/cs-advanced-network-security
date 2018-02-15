import pcap
import struct

SIZE_HEADER_ETHERNET = 14
SIZE_HEADER_IPV4 = 20

PROTOCOL_UDP = 17
PROTOCOL_TCP = 0  # TODO


def parse_ipv4_field(buffer: list) -> str:
    return '.'.join([str(struct.unpack('>B', bytes([x]))[0]) for x in buffer])


def parse_ethernet(buffer):
    pass


def parse_ip(buffer):
    # print([bin(o) for o in buffer])
    length = struct.unpack('>H', bytes(buffer[2:4]))[0]
    ttl = struct.unpack('>B', bytes([buffer[8]]))[0]
    protocol = struct.unpack('>B', bytes([buffer[9]]))[0]
    source_ip = parse_ipv4_field(buffer[12:16])
    destination_ip = parse_ipv4_field(buffer[16:20])

    print(length, ttl, protocol, source_ip, destination_ip)


def generate_bytes():
    sniffer = pcap.pcap(name='dns.cap', promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        buffer = list()
        for idx, byte in enumerate(pkt):
            buffer.append(byte)
            if idx == SIZE_HEADER_ETHERNET - 1:
                parse_ethernet(buffer)
                buffer = list()
            if idx == SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4 - 1:
                parse_ip(buffer)


if __name__ == '__main__':
    generate_bytes()
