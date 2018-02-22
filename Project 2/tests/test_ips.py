from ips import packet_loop


def test_packet_loop():
    packet_loop('arp.pcap')
