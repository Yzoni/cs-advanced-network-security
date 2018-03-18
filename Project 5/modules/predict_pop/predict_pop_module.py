from ips_module import IPSModule
from sklearn.cluster import DBSCAN


class PredictPopModule(IPSModule):

    def receive_packet(self, pkt, pkt_c):
        pass


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
        return DBSCAN().fit_predict(transmission)

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
