import pytest
import xxhash
from bitarray import bitarray


class BloomFilter:
    def __init__(self, m, k) -> None:
        """
        :param m: Bloom size
        :param k: Number of hash iterations
        """
        self.m = m
        self.k = k
        self.bits = bitarray(m)
        self.bits.setall(0)
        super().__init__()

    def _hash(self, element, seed):
        return xxhash.xxh32(element, seed=seed).intdigest() % self.m

    def add(self, element):
        for s in range(self.k):
            self.bits[self._hash(element, s)] = 1

    def might_contain(self, element) -> bool:
        for s in range(self.k):
            if self.bits[self._hash(element, s)] != 1:
                return False
        return True

    def flush(self):
        self.bits.setall(0)


@pytest.fixture
def bloom():
    return BloomFilter(10, 3)


def test_bloomfilter_add(bloom):
    bloom.add('hello')


def test_bloomfilter_contains(bloom):
    bloom.add('hello')
    assert bloom.might_contain('hello') == True
    assert bloom.might_contain('goodbye') == False


def test_bloomfilter_flush(bloom):
    bloom.add('hello')
    bloom.flush()
    assert bloom.might_contain('hello') == False
