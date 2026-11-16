# Run: python3 tests/test_hardening.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.hardening import plain_swap


def test_plain_swap():
    swaps = ('Filename\tType\tSize\tUsed\tPriority\n/dev/dm-1  partition\t36057084\t0\t-1\n/dev/zram0  partition\t8388604\t0\t100\n'
             '/dev/dm-3  partition\t100\t0\t-2\n/swapfile  file\t100\t0\t-3\n')
    layers = {'/dev/dm-1': ['lvm', 'disk', 'part'], '/dev/dm-3': ['crypt', 'part', 'disk']}
    assert plain_swap(swaps, lambda d: layers[d]) == ['/dev/dm-1']
    assert plain_swap('Filename\tType\tSize\tUsed\tPriority\n', lambda d: []) == []


if __name__ == '__main__':
    test_plain_swap(); print('ok')
