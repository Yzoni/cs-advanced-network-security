from ips_module import IPSModule

from modules.predict_pop.pop_packet import POPPacket
from ips_logger import get_logger

log = get_logger()


class PredictPopModule(IPSModule):
    def __init__(self, pop_out_file):
        self.pop_out_file = pop_out_file

    def receive_packet(self, pkt, pkt_c):
        with open(str(self.pop_out_file), mode='w') as f:
            pop = POPPacket.from_pkt(pkt)

            try:
                log.info('POP package with command {}'.format(pop.command.decode('utf_8').rstrip()))
            except (UnicodeDecodeError, UnicodeEncodeError):
                log.info('Could not decode pop')

            f.write('{}\n'.format(pop.command))


class PredictCurrentStatePop:
    def __init__(self, model=None):
        if model:
            self.model = self._load_model(model)

    def predict(self, transmission):
        cluster = self._predict_cluster(transmission)
        xor = self._predict_xor(cluster)

        state = xor
        return state

    def _predict_cluster(self, transmission):
        """
        Use DBSCAN unsupervised clustering algorithm to cluster transmissions
        together based on string similarity.
        """
        # return DBSCAN().fit_predict(transmission)
        pass

    def _predict_xor(self, cluster):
        """
        XOR all entries in cluster return largest 0 bit string
        :param cluster:
        """
        return self.model[cluster]

    def _train_xor_clusters(self):
        self.xor_model = None

        return {}

    def _load_model(self, path):
        return ''

    def save_model(self):
        pass
