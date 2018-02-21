import logging


class IPSModule:
    def receive_packet(self, pkt):
        raise NotImplementedError
