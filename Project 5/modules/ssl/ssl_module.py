from ips_module import IPSModule
from scapy.all import *
from datetime import datetime

HandshakeTypes = {
    0: 'Hello Request',
    1: 'Client Hello',
    2: 'Server Hello',
    3: 'Hello verify request',
    4: 'New session ticket',
    11: 'Certificate',
    12: 'Server key exchange',
    13: 'Certificate request',
    14: 'Server done',
    15: 'Certificate verify',
    16: 'Client key exchange',
    20: 'Finished'
}

ContentTypes = {
    0x14: 'change_cipher_spec',
    0x15: 'alert',
    0x16: 'handshake',
    0x17: 'application_data',
    0x18: 'heartbeat'
}

class SSLModule(IPSModule):

    def receive_packet(self, pkt, pkt_c):
        if pkt.haslayer(TLSHandshakes):
            for h in pkt[TLSHandshakes]:
               print(HandshakeTypes[h[TLSHandshake].type])
        try:
            print(ContentTypes[pkt[TLSRecord].content_type])
        except:
            pass

        # layers = []
        # counter = 0
        # while True:
        #     layer = pkt.getlayer(counter)
        #     if (layer != None):
        #         layers.append(layer.name)
        #     else:
        #         break
        #     counter += 1
        # print(layers)

