from collections import defaultdict


class ARPDatabase:

    def __init__(self) -> None:

        self.request_srcs = defaultdict(list)

        super().__init__()

    def store_sender_of_request(self, mac_client, ip_asked_for):
        """

        Store all ip addresses a clients should know

        :param src: Ether MAC address
        :param ip_asked_for: the target ip address
        """

        self.request_srcs[mac_client].append(ip_asked_for)

    def request_sender_should_have_ip(self, src, ip_asked_for) -> bool:
        """
        Check if a sender of an ARP request should already have the IP

        It could have acquired the ip from:
            - His own previous request and received reply
            - A received request from the IP

        :param src: Ether MAC address
        :param ip_asked_for: the target ip address
        :return: whether the sender should have already had the ip-mac binding
        """

        if ip_asked_for in self.request_srcs[src]:
            return True
        else:
            return False
