# Run: python3 tests/test_core.py (or pytest)
import atexit, os, shutil, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from pathlib import Path
from arche import core
from arche.core import Row, ALERT, WARN, INFO


def test_history():
    d = tempfile.mkdtemp(); atexit.register(shutil.rmtree, d, True)
    core.HISTORY = Path(d) / 'h.json'
    res = {'A': [Row('x', ALERT, False, None), Row('y', WARN, False, None), Row('z', INFO, True, None)]}
    for _ in range(3): h = core.record(res, 'quick')
    assert len(h) == 3 and h[-1]['score'] == 100 - 15 - 4 - 1 and h[-1]['alerts'] == 1 and h[-1]['new'] == 1
    assert oct(core.HISTORY.stat().st_mode & 0o777) == '0o600'
    assert core.spark([{'score': s} for s in (60, 80, 100)]) == '▁▄█' and core.spark([{'score': 90}]) == '▅'


if __name__ == '__main__':
    test_history(); print('ok')
