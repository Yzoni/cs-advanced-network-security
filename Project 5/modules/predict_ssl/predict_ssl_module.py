from datetime import datetime
from enum import Enum
from pathlib2 import Path
import numpy as np
import csv
import os

from ips_logger import get_logger
from ips_module import IPSModule
from modules.predict_ssl.ssl_packet import ContentTypes, HandshakeTypes, SSLPacket
from predict_ssl_database import PredictSSLDatabase
from predict_ssl_database import SSL_LOG_STATES
from util import parse_ip, parse_tcp

dir_path = Path(os.path.dirname(os.path.realpath(__file__)))
log = get_logger()


class PredictSSLModule(IPSModule):

    def __init__(self, dir_fingerprints_out):
        self.dir_fingerprints_out = dir_fingerprints_out
        self.db = PredictSSLDatabase(self.dir_fingerprints_out)

    def receive_packet(self, pkt, pkt_c):
        parsed_pkt = SSLPacket.from_pkt(pkt)

        db_states = [self._determine_state(record) for record in parsed_pkt.records]
        db_states = filter(lambda x: x is not None, db_states)

        ip_header, ip_protocol = parse_ip(pkt)
        tcp_header, tcp_header_size = parse_tcp(pkt)

        src = (ip_header['source_ip'], tcp_header['srcport'])
        dst = (ip_header['destination_ip'], tcp_header['dstport'])

        log.info('Received: {} [{}]'.format(parsed_pkt, pkt_c))

        self.db.save_new_status(src, dst, db_states)
        self.db.export_to_file(src, dst)

    def collect_training_data(self, app_name, file_name, ip=None):
        log.info('Saving train data from {} to {}'.format(app_name, file_name))

        with file_name.open(mode='w') as f:
            # Aggregate complete database
            if not ip:
                agg = None
                for k, v in self.db:
                    agg += v
                f.write('{},{}\n'.format(app_name, agg))

    @staticmethod
    def predict_app(model_file_name, to_predict_matrix):
        cost = np.inf
        app_name = 'Not found'

        with model_file_name.open(mode='r') as f:
            reader = csv.reader(f, delimiter=',')
            for row in reader:
                model_sample = row[1:]
                model_sample_name = row[0]

                new_cost = np.linalg.norm(model_sample - to_predict_matrix)
                if new_cost < cost:
                    cost = new_cost
                    app_name = model_sample_name

        return app_name, cost

    def _determine_state(self, record):

        content_type = record.content_type

        if content_type == ContentTypes.APPLICATION_DATA:
            return SSL_LOG_STATES['application_data']
        elif content_type == ContentTypes.HANDSHAKE:
            if record.handshake_type == HandshakeTypes.CLIENT_HELLO:
                return SSL_LOG_STATES['client_hello']
            elif record.handshake_type == HandshakeTypes.SERVER_HELLO:
                return SSL_LOG_STATES['server_hello']
            elif record.handshake_type == HandshakeTypes.SERVER_DONE:
                return SSL_LOG_STATES['server_done']
            elif record.handshake_type == HandshakeTypes.NEW_SESSION_TICKET:
                return SSL_LOG_STATES['new_session_ticket']
            elif record.handshake_type == HandshakeTypes.CLIENT_KEY_EXCHANGE:
                return SSL_LOG_STATES['client_key_exchange']
            elif record.handshake_type == HandshakeTypes.CERTIFICATE:
                return SSL_LOG_STATES['certificate']
            elif record.handshake_type == HandshakeTypes.CERTIFICATE_VERIFY:
                return SSL_LOG_STATES['certificate_verify']
            elif record.handshake_type == HandshakeTypes.CERTIFICATE_STATUS:
                return SSL_LOG_STATES['certificate_status']
        elif content_type == ContentTypes.ALERT:
            return SSL_LOG_STATES['alert']
        elif content_type == ContentTypes.CHANGE_CIPHER_SPEC:
            return SSL_LOG_STATES['change_cipher_spec']
        else:
            print('Content type unknown: ' + str(content_type))
