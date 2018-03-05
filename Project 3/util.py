import re
import struct


def is_valid_mac_address(mac) -> bool:
    return re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac)


def parse_ipv4_field(buffer: list) -> str:
    return '.'.join([str(struct.unpack('>B', bytes([x]))[0]) for x in buffer])


def parse_mac_field(buffer: list) -> str:
    return ':'.join(['{:0>2x}'.format(struct.unpack('>B', bytes([x]))[0]) for x in buffer])

def bit_enabled(octal, bit_num):
    if (octal & (1 << bit_num)) != 0:
        return True
    else:
        return False