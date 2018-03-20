from collections import defaultdict
from graphviz import Digraph
import numpy as np

from ips_logger import get_logger

SSL_LOG_STATES = {
    'start': 0,
    'client_hello': 1,
    'server_hello': 2,
    'certificate': 3,
    'server_done': 4,
    'change_cipher_spec': 5,
    'client_key_exchange': 6,
    'application_data': 7,
    'alert': 8,
    'end': 9,
    'new_session_ticket': 10,
    'certificate_status': 11,
    'certificate_verify': 12
}
INV_SSL_LOG_STATES = {v: k for k, v in SSL_LOG_STATES.iteritems()}

log = get_logger()


class PredictSSLDatabase:
    def __init__(self, base_out_path):
        self.db = dict()

        log.info('Saving fingerprints to {}'.format(base_out_path))

        if not base_out_path.exists():
            base_out_path.mkdir()
            log.info('Fingerprint out directory did not exist, creating it...')

        self.base_out_path = base_out_path

    def save_new_status(self, ip1port, ip2port, new_status):
        c = self.get_connection(ip1port, ip2port)
        for status in new_status:
            c.increment(status)

    def export_to_file(self, ip1port, ip2port):
        c = self.get_connection(ip1port, ip2port, aggregate=True)
        g = c.matrix_to_graphiz()
        filename = self.base_out_path / (str(c.ip2_ext[0]) + ' - ' + str(c.ip1_ssl[0]))
        g.render(str(filename))

    def get_connection(self, ip1port, ip2port, aggregate=False):
        """
        Get connection from database, if it does not exist create it
        """
        if ip1port[1] == 443:
            temp = ip1port
            ip1port = ip2port
            ip2port = temp

        if not ip1port[0] + ip2port[0] in self.db:
            self.db[ip1port[0] + ip2port[0]] = {
                ip1port[1]: TLSConnection(ip1port, ip2port)
            }
        if ip1port[1] not in self.db[ip1port[0] + ip2port[0]]:
            self.db[ip1port[0] + ip2port[0]].update({
                ip1port[1]: TLSConnection(ip1port, ip2port)
            })

        if not aggregate:
            return self.db[ip1port[0] + ip2port[0]][ip1port[1]]

        connections = None
        for port, c in self.db[ip1port[0] + ip2port[0]].iteritems():
            if not connections:
                connections = c
            else:
                connections += c
        return connections

    def __iter__(self):
        for k, v in self.db:
            yield k, v


class TLSConnection:
    def __init__(self, ip1_ssl, ip2_ext):
        self.matrix = np.zeros((len(SSL_LOG_STATES), len(SSL_LOG_STATES)))
        self.previous_status = SSL_LOG_STATES['start']
        self.ip1_ssl = ip1_ssl
        self.ip2_ext = ip2_ext

    def __str__(self):
        return str(self.ip1_ssl) + str(self.ip2_ext)

    def increment(self, new):
        self.matrix[self.previous_status][new] += 1
        self.previous_status = new

    def _normalize(self):
        summed = self.matrix.sum(axis=0)
        return np.divide(self.matrix, summed, out=np.zeros_like(self.matrix), where=summed != 0)

    def matrix_to_graphiz(self):
        n_matrix = self._normalize()

        g = Digraph('G', format='png')
        for x in range(len(n_matrix)):
            perc = n_matrix[x] / sum(n_matrix[x]) * 100
            for y in range(len(n_matrix)):
                if n_matrix[x][y] > 0:
                    g.edge(INV_SSL_LOG_STATES[x], INV_SSL_LOG_STATES[y], label='{:f}'.format(perc[y]))
        return g

    def __add__(self, other):
        self.matrix += other.matrix
        return self


def test_save_new_status():
    ip1, ip2 = '192.168.0.1', '192.168.0.2'

    s = PredictSSLDatabase()
    s.save_new_status((ip1, 443), (ip2, 2012), [SSL_LOG_STATES['client_hello']])
    assert s.db[(ip1, 443) + (ip2, 2012)].matrix[SSL_LOG_STATES['start']][SSL_LOG_STATES['client_hello']] == 1


if __name__ == '__main__':
    test_save_new_status()
