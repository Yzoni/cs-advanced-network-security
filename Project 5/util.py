import re
import struct


def is_valid_mac_address(mac):
    return re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac)


def parse_ipv4_field(buffer):
    return '.'.join([str(struct.unpack('>B', x)[0]) for x in buffer])


def parse_mac_field(buffer):
    return ':'.join(['{:0>2x}'.format(struct.unpack('>B', x)[0]) for x in buffer])


def bit_enabled(octal, bit_num):
    if (octal & (1 << bit_num)) != 0:
        return True
    else:
        return False


SIZE_HEADER_ETHERNET = 14
SIZE_HEADER_IPV4 = 20
SIZE_HEADER_UDP = 8


def parse_ip(buffer):
    ip_header = dict()

    buffer = buffer[SIZE_HEADER_ETHERNET:SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4]

    protocol = struct.unpack('>B', buffer[9])[0]
    ip_header['source_ip'] = parse_ipv4_field(buffer[12:16])
    ip_header['destination_ip'] = parse_ipv4_field(buffer[16:20])

    return ip_header, protocol


def parse_udp(buffer):
    udp_header = dict()

    udp_header['srcport'] = struct.unpack('>H', bytes(buffer[:2]))[0]
    udp_header['dstport'] = struct.unpack('>H', bytes(buffer[2:4]))[0]

    return udp_header


def parse_tcp(buffer):
    tcp_header = dict()

    buffer = buffer[SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4:]

    tcp_header['srcport'] = struct.unpack('>H', bytes(buffer[:2]))[0]
    tcp_header['dstport'] = struct.unpack('>H', bytes(buffer[2:4]))[0]

    tcp_header_size = struct.unpack('>B', bytes(buffer[12]))[0] >> 2

    return tcp_header, tcp_header_size
