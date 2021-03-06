from collections import defaultdict


class ARPDatabase:

    def __init__(self):

        self.mac_stored_ips = defaultdict(list)


    def store_mac_should_know(self, mac_client, ip_asked_for):
        """

        Store all ip addresses a clients should know

        :param src: Ether MAC address
        :param ip_asked_for: the target ip address
        """

        self.mac_stored_ips[mac_client].append(ip_asked_for)

    def request_sender_should_have_ip(self, src, ip_asked_for):
        """
        Check if a sender of an ARP request should already have the IP

        It could have acquired the ip from:
            - His own previous request and received reply
            - A received request from the IP

        :param src: Ether MAC address
        :param ip_asked_for: the target ip address
        :return: whether the sender should have already had the ip-mac binding
        """

        if ip_asked_for in self.mac_stored_ips[src]:
            return True
        else:
            return False
