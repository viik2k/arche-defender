# Run: python3 tests/test_monitor.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.core import Row, INFO, WARN, ALERT
from arche.monitor import fresh_findings


def test_fresh():
    res = {'A': [Row('ok', INFO, False, None), Row('bad', ALERT, False, None), Row('meh', WARN, False, None)],
           'B': [Row('new thing', INFO, True, None)]}
    flagged, fresh = fresh_findings(res, {'A: meh'})
    assert set(flagged) == {'A: bad', 'A: meh', 'B: new thing'}
    assert fresh == ['A: bad', 'B: new thing']   # alerts first, already-told skipped
    assert fresh_findings(res, set(flagged))[1] == []


if __name__ == '__main__':
    test_fresh(); print('ok')
