from util import parse_tcp, SIZE_HEADER_ETHERNET, SIZE_HEADER_IPV4


class POPPacket:
    fields = ['command']

    def __init__(self, command):
        self.command = command

    @classmethod
    def from_pkt(cls, pkt):
        offset_begin_t = SIZE_HEADER_ETHERNET + SIZE_HEADER_IPV4
        tcp_header, tcp_header_size = parse_tcp(pkt)
        pop_offset = offset_begin_t + tcp_header_size + 5

        pop_msg = pkt[pop_offset:]

        return cls(command=pop_msg)
