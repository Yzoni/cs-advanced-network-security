class IPSModule:
    """
    Modules should extend this class
    """

    def receive_packet(self, pkt):
        raise NotImplementedError
