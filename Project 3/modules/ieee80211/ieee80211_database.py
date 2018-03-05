from collections import defaultdict
from collections import Counter


class IEEE80211Database:

    def __init__(self, iv_threshold) -> None:
        self.iv_threshold = iv_threshold
        self.src_iv = defaultdict(list)

        super().__init__()

    def store_source_iv(self, src, iv):
        self.src_iv[src].append(iv)

    def past_wep_replay_threshold(self, src) -> bool:
        most_common = Counter(self.src_iv[src]).most_common(5)
        if most_common[0][1] >= self.iv_threshold:
            return True

    def clear_source_iv(self, src):
        self.src_iv.pop(src)
