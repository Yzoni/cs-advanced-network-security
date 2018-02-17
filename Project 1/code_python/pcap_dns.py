import pcap
import struct
from pprint import pprint

SIZE_HEADER_ETHERNET = 14
SIZE_HEADER_IPV4 = 20
SIZE_HEADER_UDP = 8

PROTOCOL_UDP = 17
PROTOCOL_TCP = 0  # TODO


def parse_ipv4_field(buffer: list) -> str:
    return '.'.join([str(struct.unpack('>B', bytes([x]))[0]) for x in buffer])


def parse_ethernet(buffer):
    # print([bin(o) for o in buffer])
    return {}


def parse_ip(buffer):
    # print([bin(o) for o in buffer])
    ip_header = dict()

    ip_header['length'] = struct.unpack('>H', bytes(buffer[2:4]))[0]
    ip_header['ttl'] = struct.unpack('>B', bytes([buffer[8]]))[0]
    ip_header['protocol'] = struct.unpack('>B', bytes([buffer[9]]))[0]
    ip_header['source_ip'] = parse_ipv4_field(buffer[12:16])
    ip_header['destination_ip'] = parse_ipv4_field(buffer[16:20])

    pprint(ip_header)

    return ip_header


def parse_udp(buffer):
    print([bin(o) for o in buffer])
    udp_header = dict()

    udp_header['srcport'] = struct.unpack('>H', bytes(buffer[:2]))[0]
    udp_header['dstport'] = struct.unpack('>H', bytes(buffer[2:4]))[0]
    udp_header['length'] = struct.unpack('>H', bytes(buffer[4:6]))[0]
    udp_header['checksum'] = struct.unpack('>H', bytes(buffer[6:8]))[0]

    pprint(udp_header)

    return udp_header


def parse_tcp(buffer):
    return {}


def parse_dns(buffer):
    dns_header = dict()

    dns_header['id'] = struct.unpack('>H', bytes(buffer[:2]))[0]
    dns_header['difficult'] = struct.unpack('>H', bytes(buffer[2:4]))[0]
    dns_header['qdcount'] = struct.unpack('>H', bytes(buffer[4:6]))[0]
    dns_header['ancount'] = struct.unpack('>H', bytes(buffer[6:8]))[0]
    dns_header['nscount'] = struct.unpack('>H', bytes(buffer[8:10]))[0]
    dns_header['arcount'] = struct.unpack('>H', bytes(buffer[10:12]))[0]

    pprint(dns_header)



    return dns_header


def generate_bytes():
    offset_begin_t = SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4

    sniffer = pcap.pcap(name='dns.cap', promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        ethernet_header = parse_ip(pkt[:SIZE_HEADER_ETHERNET])
        ip_header = parse_ip(pkt[SIZE_HEADER_ETHERNET:SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4])
        if ip_header['protocol'] == PROTOCOL_UDP:
            udp_header = parse_udp(
                pkt[offset_begin_t:offset_begin_t + SIZE_HEADER_UDP])
            dns = parse_dns(pkt[offset_begin_t + SIZE_HEADER_UDP:])
        elif ip_header['protocol'] == PROTOCOL_TCP:  # TODO
            tcp_header = parse_tcp(
                pkt[offset_begin_t:offset_begin_t + SIZE_HEADER_UDP])
            dns = parse_dns(pkt[offset_begin_t + SIZE_HEADER_UDP:])
        else:
            print('Irrelevant protocol')
        return


if __name__ == '__main__':
    generate_bytes()
