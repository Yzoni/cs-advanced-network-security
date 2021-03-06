from ips_response import IPSResponse


class IPSModule:
    """
    Modules should extend this class
    """

    def receive_packet(self, pkt, pkt_c) -> IPSResponse:
        raise NotImplementedError
