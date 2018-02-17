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
PROTOCOL_TCP = 6

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
    tcp_header = dict()

    tcp_header['srcport'] = struct.unpack('>H', bytes(buffer[:2]))[0]
    tcp_header['dstport'] = struct.unpack('>H', bytes(buffer[2:4]))[0]

    tcp_header_size = buffer[12] >> 2

    return tcp_header, tcp_header_size

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
        print('    Failed to parse questions')
        return dns

    try:
        answers = list()
        for _ in range(dns_header['ancount']):
            answer, offset = parse_dns_resource(buffer[SIZE_DNS_HEADER:], offset)
            answers.append(answer)
        dns['answers'] = answers
    except:
        print('    Failed to parse answers')
        return dns

    try:
        authorities = list()
        for _ in range(dns_header['nscount']):
            authority, offset = parse_dns_resource(buffer[SIZE_DNS_HEADER:], offset)
            authorities.append(authority)
        dns['authorities'] = authorities
    except:
        print('    Failed to parse authorities')
        return dns
    try:
        additionals = list()
        for _ in range(dns_header['arcount']):
            additional, offset = parse_dns_resource(buffer[SIZE_DNS_HEADER:], offset)
            additionals.append(additional)
        dns['additionals'] = additionals
    except:
        print('    Failed to parse additionals')
        return dns

    return dns


def parse_dns_question(buffer, offset):
    dns_question = dict()

    qname, offset = parse_dns_label(buffer, offset)
    dns_question['qname'] = qname
    dns_question['qtype'] = QTYPES[struct.unpack('>H', bytes(buffer[offset:offset + 2]))[0]]
    dns_question['qclass'] = QCLASS[struct.unpack('>H', bytes(buffer[offset + 2:offset + 4]))[0]]

    return dns_question, offset + 4


def parse_dns_resource(buffer, offset):
    dns_resource = dict()

    rname, offset = parse_dns_label(buffer, offset)
    dns_resource['name'] = rname
    dns_resource['type'] = QTYPES[struct.unpack('>H', bytes(buffer[offset:offset + 2]))[0]]
    dns_resource['class'] = QCLASS[struct.unpack('>H', bytes(buffer[offset + 2:offset + 4]))[0]]
    dns_resource['ttl'] = struct.unpack('>I', bytes(buffer[offset + 4:offset + 8]))[0]

    rdlength = struct.unpack('>H', bytes(buffer[offset + 8:offset + 10]))[0]
    dns_resource['rdata'] = parse_dns_resource_rdata(buffer, offset + 10, rdlength, dns_resource['type'])

    return dns_resource, offset + 10 + rdlength


def parse_dns_resource_rdata(buffer, offset, rdlength, type):
    if type == 'CNAME':
        cname, offset = parse_dns_label(buffer, offset)
        return cname
    elif type == 'HINFO':
        pass
    elif type == 'MB':
        pass
    elif type == 'MD':
        pass
    elif type == 'MF':
        pass
    elif type == 'MG':
        pass
    elif type == 'MINFO':
        pass
    elif type == 'MR':
        pass
    elif type == 'MX':
        pass
    elif type == 'NULL':
        pass
    elif type == 'NS':
        pass
    elif type == 'PTR':
        pass
    elif type == 'SOA':
        pass
    elif type == 'TXT':
        return binascii.b2a_qp(buffer[offset:offset + rdlength]).decode("utf-8", "strict")
    elif type == 'A':
        return parse_ipv4_field(buffer[offset:offset + 4])
    elif type == 'WKS':
        pass
    else:
        print('Could not parse RDATA, unknown type')


def label_is_pointer(octet):
    if (octet >> 6 & 0b11) == 0b11:  # Pointer
        return True
    elif (octet >> 6 | 0b00) == 0b00:  # Label
        return False
    else:
        print('Unknown label type')


def parse_dns_label(buffer, offset):
    name = b''
    jumps = list()
    name, offset, jumps = parse_dns_label_recursive(name, offset, buffer, jumps)

    if len(jumps) > 0:  # Restore offset to the actual current resource
        offset = jumps[0] + 1

    return binascii.b2a_qp(name).decode(), offset


def parse_dns_label_recursive(name, offset, buffer, jumps):
    """
    Recursively parse compressed labels

    :param name: Final full label
    :param offset: Offset in buffer
    :param buffer: Buffer from the first question/query
    :param jumps: Keep track of offset where we originally came from when jumped to pointer location
    :return:
    """
    while True:
        if buffer[offset] == 0:  # Last label 0 octet
            return name[:-1], offset + 1, jumps
        if label_is_pointer(buffer[offset]):
            jumps.append(offset + 1)
            offset = buffer[offset + 1] - SIZE_DNS_HEADER
            return parse_dns_label_recursive(name, offset, buffer, jumps)
        else:
            label_length = buffer[offset] & (1 << 6) - 1  # last 6 bits indicate length of label
            name += buffer[offset + 1:offset + label_length + 1]
            name += b'.'
            return parse_dns_label_recursive(name, offset + label_length + 1, buffer, jumps)


def pcap_loop(pcap_file, json_out):
    offset_begin_t = SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4

    sniffer = pcap.pcap(name=pcap_file, promisc=True, immediate=True, timeout_ms=50)

    pkts_json = dict()
    pkt_counter = 0
    for ts, pkt in sniffer:
        pkt_counter += 1
        # if pkt_counter != 1: continue
        print('Parsing packet {:d}...'.format(pkt_counter))

        pkt_json = dict()

        try:
            ip_header, ip_protocol = parse_ip(pkt[SIZE_HEADER_ETHERNET:SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4])
            pkt_json['ipv4'] = ip_header

            if ip_protocol == PROTOCOL_UDP:
                udp_header = parse_udp(pkt[offset_begin_t:offset_begin_t + SIZE_HEADER_UDP])
                pkt_json['ipv4']['srcport'] = udp_header['srcport']
                pkt_json['ipv4']['dstport'] = udp_header['dstport']

                dns = parse_dns(pkt[offset_begin_t + SIZE_HEADER_UDP:])
            elif ip_protocol == PROTOCOL_TCP:  # TODO
                tcp_header, tcp_header_size = parse_tcp(pkt[offset_begin_t:])
                pkt_json['ipv4']['srcport'] = tcp_header['srcport']
                pkt_json['ipv4']['dstport'] = tcp_header['dstport']
                dns = parse_dns(pkt[offset_begin_t + tcp_header_size:])
            else:
                dns = dict()
                print('Irrelevant protocol')

            pkt_json['header'] = dns
            pkts_json['packet_{:d}'.format(pkt_counter)] = pkt_json
        except:
            print('    Failed to pare packet {}'.format(pkt_counter))

    with open(json_out, 'w') as outfile:
        json.dump(pkts_json, outfile)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP DNS PARSING')
    parser.add_argument('pcap_in', type=str, help='pcap file input')
    parser.add_argument('json_out', type=str, help='JSON out file')
    args = parser.parse_args()

    if args.pcap_in and args.json_out:
        pcap_loop(args.pcap_in, args.json_out)
