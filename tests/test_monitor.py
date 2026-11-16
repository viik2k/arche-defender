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


def test_watch_run_keeps_other_notices():   # a folder-watch pass must not forget what the hourly scan already announced
    import json, tempfile
    from pathlib import Path
    from arche import monitor, core
    core.load_all()
    monitor.SEEN, monitor.have = Path(tempfile.mkdtemp()) / 'n.json', lambda c: False   # no real notifications
    monitor.SEEN.write_text(json.dumps({'told': ['Other: x', 'Dropped files: gone'], 'last': 't'}))
    monitor.run(['Dropped files'])
    s = json.loads(monitor.SEEN.read_text())
    assert 'Other: x' in s['told'] and 'Dropped files: gone' not in s['told'] and s['last'] == 't'


if __name__ == '__main__':
    test_fresh(); test_watch_run_keeps_other_notices(); print('ok')
