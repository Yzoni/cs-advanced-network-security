from collections import defaultdict
from collections import Counter


class IEEE80211Database:

    def __init__(self, iv_threshold) -> None:
        self.iv_threshold = iv_threshold
        self.src_iv = defaultdict(list)

        super().__init__()

    def store_source_iv(self, src, iv):
        self.src_iv[src].append(iv)

    def past_wep_replay_threshold(self, src) -> (bool, str):
        most_common = Counter(self.src_iv[src]).most_common(5)
        most = most_common[0]
        if most[1] >= self.iv_threshold:
            return True, most[0]
        return False, most[0]

    def clear_source_iv(self, src, iv):
        self.src_iv[src] = list(filter(lambda x: x != iv, self.src_iv[src]))
