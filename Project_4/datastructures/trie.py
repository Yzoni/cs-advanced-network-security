from bitarray import bitarray


class Trie:
    def __init__(self, root_data='', strides=1) -> None:
        self.strides = strides
        self.root = self._Node()
        self.root.data = root_data
        super().__init__()

    def add(self, bits: bitarray, data):
        node = self.root
        for idx, bit in enumerate(bits):
            if bit == 0:
                if not node.zero:
                    node.zero = self._Node()
                node = node.zero
            if bit == 1:
                if not node.one:
                    node.one = self._Node()
                node = node.one

            if idx == len(bits) - 1:
                node.data = data

    def longest_prefix(self, bits: bitarray):
        node = self.root

        def recurse(bits, node):
            if bits[0]:
                if node.one:
                    node = node.one
            else:
                if node.zero:
                    node = node.zero

            if len(bits) > 1:
                return recurse(bits[1:], node)

            return node.data

        return recurse(bits, node)

    class _Node:
        data = None
        zero = None
        one = None


def test_trie_add():
    trie = Trie(root_data='ACCEPT', strides=1)
    trie.add(bitarray('101'), 'DROP')


def test_trie_longest_prefix_equal():
    trie = Trie(root_data='ACCEPT', strides=1)
    trie.add(bitarray('101'), 'DROP')

    assert trie.longest_prefix(bitarray('101')) == 'DROP'


def test_trie_longest_prefix_longer():
    trie = Trie(root_data='ACCEPT', strides=1)
    trie.add(bitarray('101'), 'DROP')

    assert trie.longest_prefix(bitarray('1010001001')) == 'DROP'

