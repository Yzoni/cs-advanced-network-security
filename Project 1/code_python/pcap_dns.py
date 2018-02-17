import pcap
import struct
import binascii
import json
import argparse

from util import bit_enabled
from util import parse_4_bit_opcode
from util import parse_4_bit_rcode

SIZE_HEADER_ETHERNET = 14
SIZE_HEADER_IPV4 = 20
SIZE_HEADER_UDP = 8
SIZE_DNS_HEADER = 12

PROTOCOL_UDP = 17
PROTOCOL_TCP = 0  # TODO

QCLASS = {
    1: 'IN',
    2: 'CS',
    3: 'CH',
    4: 'HS',
    255: '*'
}

QTYPES = {
    1: 'A',
    2: 'NS',
    3: 'MD',
    4: 'MF',
    5: 'CNAME',
    6: 'SOA',
    7: 'MB',
    8: 'MG',
    9: 'MR',
    10: 'NULL',
    11: 'WKS',
    12: 'PTR',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT',
    252: 'AXFR',
    253: 'MAILB',
    254: 'MAILA',
    255: '*'
}

OPCODES = ['QUERY', 'IQUERY', 'STATUS', 'RESERVED']
RCODES = ['NOERROR', 'FERROR', 'SFAILURE', 'NERROR', 'NIMPLEMENTED', 'REFUSED', 'RESERVED']


def parse_ipv4_field(buffer: list) -> str:
    return '.'.join([str(struct.unpack('>B', bytes([x]))[0]) for x in buffer])


def parse_ethernet(buffer):
    # print([bin(o) for o in buffer])
    return {}


def parse_ip(buffer):
    ip_header = dict()

    protocol = struct.unpack('>B', bytes([buffer[9]]))[0]
    ip_header['source_ip'] = parse_ipv4_field(buffer[12:16])
    ip_header['destination_ip'] = parse_ipv4_field(buffer[16:20])

    return ip_header, protocol


def parse_udp(buffer):
    udp_header = dict()

    udp_header['srcport'] = struct.unpack('>H', bytes(buffer[:2]))[0]
    udp_header['dstport'] = struct.unpack('>H', bytes(buffer[2:4]))[0]

    return udp_header


def parse_tcp(buffer):
    return {}


def parse_dns(buffer):
    dns = dict()

    dns_header = dict()
    dns_header['id'] = struct.unpack('>H', bytes(buffer[:2]))[0]

    dns_header['difficult'] = struct.unpack('>H', bytes(buffer[2:4]))[0]
    dns_header['qr'] = bit_enabled(buffer[3], 7)
    dns_header['opcode'] = OPCODES[parse_4_bit_opcode(buffer[3])]
    dns_header['aa'] = bit_enabled(buffer[3], 2)
    dns_header['tc'] = bit_enabled(buffer[3], 1)
    dns_header['rd'] = bit_enabled(buffer[3], 0)
    dns_header['rcode'] = RCODES[parse_4_bit_rcode(buffer[4])]
    dns_header['qdcount'] = struct.unpack('>H', bytes(buffer[4:6]))[0]
    dns_header['ancount'] = struct.unpack('>H', bytes(buffer[6:8]))[0]
    dns_header['nscount'] = struct.unpack('>H', bytes(buffer[8:10]))[0]
    dns_header['arcount'] = struct.unpack('>H', bytes(buffer[10:12]))[0]
    dns['header'] = dns_header

    offset = 0

    try:
        questions = list()
        for _ in range(dns_header['qdcount']):
            question, offset = parse_dns_question(buffer[SIZE_DNS_HEADER:], offset)
            questions.append(question)
        dns['question'] = questions
    except:
        return dns

    try:
        answers = list()
        for _ in range(dns_header['ancount']):
            answer, offset = parse_dns_resource(buffer[SIZE_DNS_HEADER:], offset)
            answers.append(answer)
        dns['answers'] = answers
    except:
        return dns

    try:
        authorities = list()
        for _ in range(dns_header['nscount']):
            authority, offset = parse_dns_resource(buffer[SIZE_DNS_HEADER:], offset)
            authorities.append(authority)
        dns['authorities'] = authorities
    except:
        return dns
    try:
        additionals = list()
        for _ in range(dns_header['arcount']):
            additional, offset = parse_dns_resource(buffer[SIZE_DNS_HEADER:], offset)
            additionals.append(additional)
        dns['additionals'] = additionals
    except:
        return dns

    return dns


def parse_dns_question(buffer, offset):
    dns_question = dict()

    qname, offset = parse_dns_label(buffer, offset)
    dns_question['qname'] = binascii.b2a_qp(qname).decode("utf-8", "strict")
    dns_question['qtype'] = QTYPES[struct.unpack('>H', bytes(buffer[offset:offset + 2]))[0]]
    dns_question['qclass'] = QCLASS[struct.unpack('>H', bytes(buffer[offset + 2:offset + 4]))[0]]

    return dns_question, offset + 4


def parse_dns_resource(buffer, offset):
    dns_resource = dict()

    rname, offset = parse_dns_label(buffer, offset)
    dns_resource['name'] = binascii.b2a_qp(rname).decode("utf-8", "strict")
    dns_resource['type'] = QTYPES[struct.unpack('>H', bytes(buffer[offset:offset + 2]))[0]]
    dns_resource['class'] = QCLASS[struct.unpack('>H', bytes(buffer[offset + 2:offset + 4]))[0]]
    dns_resource['ttl'] = struct.unpack('>I', bytes(buffer[offset + 4:offset + 8]))[0]

    rdlength = struct.unpack('>H', bytes(buffer[offset + 8:offset + 10]))[0]
    dns_resource['rdata'] = bytes(buffer[offset + 10:offset + 10 + rdlength])[0]

    return dns_resource, offset


def label_is_pointer(octet):
    if (octet >> 6 & 0b11) == 0b11:  # Pointer
        return True
    elif (octet >> 6 | 0b00) == 0b00:  # Label
        return False
    else:
        print('Unknown label type')


def parse_dns_label_text(buffer, offset):
    labels = b''
    while True:
        label_length = buffer[offset] & (1 << 6) - 1  # last 6 bits indicate length of label
        labels += buffer[offset + 1:offset + label_length + 1]
        offset += label_length + 1
        if buffer[offset] == 0:  # Last label 0 octet
            break
        labels += b'.'
    return labels, offset


def parse_dns_label(buffer, offset):
    if label_is_pointer(buffer[offset]):
        points_to_location = buffer[offset + 1] - SIZE_DNS_HEADER  # TODO 1.8 octets?
        labels, _ = parse_dns_label_text(buffer, points_to_location)
        offset += 1
    else:
        labels, offset = parse_dns_label_text(buffer, offset)
    return labels, offset + 1


def pcap_loop(pcap_file, json_out):
    offset_begin_t = SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4

    sniffer = pcap.pcap(name=pcap_file, promisc=True, immediate=True, timeout_ms=50)

    pkts_json = dict()
    pkt_counter = 0
    for ts, pkt in sniffer:
        pkt_counter += 1
        pkt_json = dict()

        ip_header, ip_protocol = parse_ip(pkt[SIZE_HEADER_ETHERNET:SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4])
        pkt_json['ipv4'] = ip_header

        if ip_protocol == PROTOCOL_UDP:
            udp_header = parse_udp(pkt[offset_begin_t:offset_begin_t + SIZE_HEADER_UDP])
            pkt_json['ipv4']['srcport'] = udp_header['srcport']
            pkt_json['ipv4']['dstport'] = udp_header['dstport']

            dns = parse_dns(pkt[offset_begin_t + SIZE_HEADER_UDP:])
        elif ip_protocol == PROTOCOL_TCP:  # TODO
            tcp_header = parse_tcp(pkt[offset_begin_t:offset_begin_t + SIZE_HEADER_UDP])
            pkt_json['ipv4']['srcport'] = tcp_header['srcport']
            pkt_json['ipv4']['dstport'] = tcp_header['dstport']
            dns = parse_dns(pkt[offset_begin_t + SIZE_HEADER_UDP:])
        else:
            dns = dict()
            print('Irrelevant protocol')

        pkt_json['header'] = dns
        pkts_json['packet_{:d}'.format(pkt_counter)] = pkt_json

    with open(json_out, 'w') as outfile:
        json.dump(pkts_json, outfile)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP DNS PARSING')
    parser.add_argument('pcap_in', type=str, help='pcap file input')
    parser.add_argument('json_out', type=str, help='JSON out file')
    args = parser.parse_args()

    if args.pcap_in and args.json_out:
        pcap_loop(args.pcap_in, args.json_out)
