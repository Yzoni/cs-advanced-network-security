from scapy.all import *
from datetime import datetime
from enum import Enum
from pathlib2 import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.ssl_tls import TLSRecord, TLSHandshake, TLSHandshakes

from ips_logger import get_logger
from ips_module import IPSModule
from predict_ssl_database import PredictSSLDatabase
from predict_ssl_database import SSL_LOG_STATES

dir_path = Path(os.path.dirname(os.path.realpath(__file__)))
log = get_logger()


class HandshakeTypes(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    NEW_SESSION_TICKET = 4
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_STATUS = 22
    OTHER = 9999


class ContentTypes(Enum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18
    OTHER = 9999


class PredictSSLModule(IPSModule):

    def __init__(self, dir_fingerprints_out):
        self.dir_fingerprints_out = dir_fingerprints_out
        self.db = PredictSSLDatabase(self.dir_fingerprints_out)

    def receive_packet(self, pkt, pkt_c):
        content_type = self._get_tls_content_type(pkt)
        if not content_type:
            return

        handshake_types = self._get_tls_handshake_types(pkt)

        db_states = self._determine_states(content_type, handshake_types)

        self.db.save_new_status((pkt[IP].src, pkt[TCP].sport), (pkt[IP].dst, pkt[TCP].dport), db_states)
        self.db.export_to_file((pkt[IP].src, pkt[TCP].sport), (pkt[IP].dst, pkt[TCP].dport))

    def collect_training_data(self, app_name, file_name, ip=None):
        log.info('Saving train data from {} to {}'.format(app_name, file_name))

        with file_name.open() as f:
            # Aggregate complete database
            if not ip:
                agg = None
                for k, v in self.db:
                    agg += v
                f.write('{},{}\n'.format(app_name, agg))

    def _determine_states(self, content_type, handshake_types):
        db_states = list()

        if content_type == ContentTypes.APPLICATION_DATA:
            db_states.append(SSL_LOG_STATES['application_data'])
        elif content_type == ContentTypes.HANDSHAKE:
            for h_type in handshake_types:
                if h_type == HandshakeTypes.CLIENT_HELLO:
                    db_states.append(SSL_LOG_STATES['client_hello'])
                elif h_type == HandshakeTypes.SERVER_HELLO:
                    db_states.append(SSL_LOG_STATES['server_hello'])
                elif h_type == HandshakeTypes.SERVER_DONE:
                    db_states.append(SSL_LOG_STATES['server_done'])
                elif h_type == HandshakeTypes.NEW_SESSION_TICKET:
                    db_states.append(SSL_LOG_STATES['new_session_ticket'])
                elif h_type == HandshakeTypes.CLIENT_KEY_EXCHANGE:
                    db_states.append(SSL_LOG_STATES['client_key_exchange'])
                elif h_type == HandshakeTypes.CERTIFICATE:
                    db_states.append(SSL_LOG_STATES['certificate'])
                elif h_type == HandshakeTypes.CERTIFICATE_VERIFY:
                    db_states.append(SSL_LOG_STATES['certificate_verify'])
                elif h_type == HandshakeTypes.CERTIFICATE_STATUS:
                    db_states.append(SSL_LOG_STATES['certificate_status'])
        elif content_type == ContentTypes.ALERT:
            db_states.append(SSL_LOG_STATES['alert'])
        elif content_type == ContentTypes.CHANGE_CIPHER_SPEC:
            db_states.append(SSL_LOG_STATES['change_cipher_spec'])
        else:
            print('Content type unknown: ' + str(content_type))

        return db_states

    def _get_tls_content_type(self, pkt):
        try:
            if pkt.haslayer(TLSRecord):
                return ContentTypes(pkt[TLSRecord].content_type)
            else:
                return None
        except ValueError:
            return ContentTypes.OTHER

    def _get_tls_handshake_types(self, pkt):
        try:
            if pkt.haslayer(TLSHandshakes):
                return [HandshakeTypes(h[TLSHandshake].type) for h in pkt[TLSHandshakes]]
            return []
        except ValueError:
            return [HandshakeTypes.OTHER]
