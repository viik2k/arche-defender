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
    import atexit, json, shutil, tempfile
    from pathlib import Path
    from arche import monitor, core
    core.load_all()
    d = tempfile.mkdtemp(); atexit.register(shutil.rmtree, d, True)
    monitor.SEEN, monitor.have = Path(d) / 'n.json', lambda c: False   # no real notifications
    monitor.SEEN.write_text(json.dumps({'told': ['Other: x', 'Dropped files: gone'], 'last': 't'}))
    monitor.run(['Dropped files'])
    s = json.loads(monitor.SEEN.read_text())
    assert 'Other: x' in s['told'] and 'Dropped files: gone' not in s['told'] and s['last'] == 't'



def test_hourly_run_refreshes_intel():
    import atexit, shutil, tempfile
    from pathlib import Path
    from arche import monitor, intel, cli
    d = tempfile.mkdtemp(); atexit.register(shutil.rmtree, d, True)
    calls, real = [], (intel.feed_age_days, intel.update, cli.pick, cli.scan_all, monitor.record, monitor.SEEN, monitor.have)
    intel.update, cli.pick, cli.scan_all = lambda: calls.append(1) or 'Updated 3 feeds', lambda *a: [], lambda *a: {}
    monitor.record, monitor.SEEN, monitor.have = lambda *a: None, Path(d) / 'n.json', lambda c: False
    try:
        for age in (None, 3, 0): intel.feed_age_days = lambda: age; monitor.run()
        monitor.run(['Dropped files'])   # a folder-watch pass never goes online
    finally: intel.feed_age_days, intel.update, cli.pick, cli.scan_all, monitor.record, monitor.SEEN, monitor.have = real
    assert calls == [1, 1], calls


if __name__ == '__main__':
    test_fresh(); test_watch_run_keeps_other_notices(); test_hourly_run_refreshes_intel(); print('ok')
