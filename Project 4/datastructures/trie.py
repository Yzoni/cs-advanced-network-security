"""
For strides higher than one padding is used. This means all possible endings are generated
and inserted with the given data. If for a padded entry there already exists an entry with data, the new
entry is discarded.
"""
from bitarray import bitarray
import itertools


class Trie:
    def __init__(self, root_data='', strides=1) -> None:
        self.strides = strides
        self.root = self._Node()
        self.root.data = root_data
        super().__init__()

    def add(self, bits: bitarray, data):
        def recurse(bits, node, data):
            bit = bits[:self.strides]

            if len(bit) < self.strides:  # Last stride
                perms = self._padded_permutations(bit, self.strides)
                for p in perms:
                    if not node.branches.get(str(p), None) or not node.branches[str(p)].data:
                        node.branches[str(p)] = self._Node(data=data)
            else:
                next_node = node.branches.get(str(bit), None)
                if next_node:  # Node already exists
                    node = next_node
                else:
                    node.branches[str(bit)] = self._Node()
                    node = node.branches[str(bit)]

                if len(bits[self.strides:]) == 0:
                    node.data = data

                if len(bits) > self.strides:
                    return recurse(bits[self.strides:], node, data)

        return recurse(bits, self.root, data)

    def longest_prefix(self, bits: bitarray):
        def recurse(bits, node, last_matched_data):
            bit = bits[:self.strides]

            if node.data:
                last_matched_data = node.data

            if len(bit) < self.strides:
                perms = self._padded_permutations(bit, self.strides)
                for p in perms:
                    next_node = node.branches.get(str(p), None)
                    if next_node and next_node.data:
                        return next_node.data
            else:
                next_node = node.branches.get(str(bit), None)
                if next_node:
                    return recurse(bits[self.strides:], next_node, last_matched_data)

            return last_matched_data

        return recurse(bits, self.root, self.root.data)

    @staticmethod
    def _padded_permutations(bits: bitarray, strides):
        padding_size = strides - len(bits)
        perm = [p for p in itertools.product([1, 0], repeat=padding_size)]
        return [bits + bitarray(p) for p in perm]

    class _Node:

        def __init__(self, branches=None, data=None) -> None:
            if branches is None:
                self.branches = dict()
            self.data = data
            super().__init__()


def test_padding():
    assert Trie._padded_permutations(bitarray('10'), 3) == [bitarray('101'), bitarray('100')]


def test_trie_add():
    trie = Trie(root_data='ACCEPT', strides=1)
    trie.add(bitarray('101'), 'DROP')


def test_trie_add_multibit():
    trie = Trie(root_data='ACCEPT', strides=3)
    trie.add(bitarray('101'), 'DROP')


def test_trie_add_multibit_padding():
    trie = Trie(root_data='ACCEPT', strides=3)
    trie.add(bitarray('1010'), 'DROP')


def test_trie_longest_prefix():
    trie = Trie(root_data='ACCEPT', strides=1)
    trie.add(bitarray('101'), 'DROP')

    assert trie.longest_prefix(bitarray('101')) == 'DROP'


def test_trie_longest_prefix_longer():
    trie = Trie(root_data='ACCEPT', strides=1)
    trie.add(bitarray('101'), 'DROP')

    assert trie.longest_prefix(bitarray('1010001001')) == 'DROP'


def test_trie_longest_prefix_longer_2():
    trie = Trie(root_data='ACCEPT', strides=1)
    trie.add(bitarray('101'), 'DROP')
    trie.add(bitarray('10101'), 'ACCEPT')
    trie.longest_prefix(bitarray('1010001001'))

    assert trie.longest_prefix(bitarray('1010001001')) == 'DROP'
    assert trie.longest_prefix(bitarray('101010101')) == 'ACCEPT'


def test_trie_longest_prefix_multibit_longer():
    trie = Trie(root_data='ACCEPT', strides=3)
    trie.add(bitarray('101010'), 'DROP')

    assert trie.longest_prefix(bitarray('101010')) == 'DROP'


def test_trie_longest_prefix_multibit_padding():
    trie = Trie(root_data='ACCEPT', strides=3)
    trie.add(bitarray('10101'), 'DROP')
    trie.add(bitarray('10100'), 'ACCEPT')
    assert trie.longest_prefix(bitarray('10101')) == 'DROP'
    assert trie.longest_prefix(bitarray('10100')) == 'ACCEPT'


def test_trie_longest_prefix_multibit_padding_2():
    trie = Trie(root_data='ACCEPT', strides=3)
    trie.add(bitarray('101010'), 'DROP')
    trie.add(bitarray('10101'), 'ACCEPT')
    assert trie.longest_prefix(bitarray('101010')) == 'DROP'
    assert trie.longest_prefix(bitarray('10101')) == 'ACCEPT'