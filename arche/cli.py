# Command line: the GUI by default, headless scans for scripts and timers, and the registered actions.
import argparse, json, sys, tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from . import core, __version__
from .core import CHECKS, ACTIONS, INFO, WARN, ALERT, run_check, load_baseline, load_all

SEV = {INFO: 'info', WARN: 'warn', ALERT: 'alert'}
MARK = {INFO: '+', WARN: '-', ALERT: '!'}


def pick(full=False, only=None):
    return [n for n, c in CHECKS.items() if (n in only if only else full or not c.slow)]


def scan_all(base, names):
    with ThreadPoolExecutor(6) as ex: return dict(zip(names, ex.map(lambda n: run_check(n, base), names)))


def as_json(res, base):
    return {'time': core.stamp(), 'score': core.score(res), 'baseline': base is not None,
            'checks': {n: {'family': CHECKS[n].family, 'rows': [{'text': r.text, 'severity': SEV[r.sev], 'new': r.new, 'fix': r.fix}
                                                                for r in rows]} for n, rows in res.items()}}


def exit_code(res):
    rows = [r for rs in res.values() for r in rs]
    return 2 if any(r.sev == ALERT for r in rows) else 1 if any(r.sev == WARN or r.new for r in rows) else 0


def selftest():
    fail = 0
    if core.ver('/x/app-1.0.9267/a') != '/x/app-*/a': print('FAIL ver'); fail += 1
    CHECKS['_t'] = core.Check('Test', lambda: [core.item('known'), core.item('fresh'), core.alert('bad'), core.item('fresh'),
                                               core.warn('meh', fix='do x'), core.item('meh')], False)
    r = run_check('_t', {'_t': ['known']})
    if [x.text for x in r if x.new] != ['fresh'] or [x.text for x in r if x.sev == ALERT] != ['bad'] or \
       [(x.text, x.fix) for x in r if x.sev == WARN] != [('meh', 'do x')]: print('FAIL baseline diff'); fail += 1
    if any(x.new for x in run_check('_t', {})): print('FAIL check missing from baseline counted as new'); fail += 1
    real, core.IGNORE_FILE = core.IGNORE_FILE, Path(tempfile.mkdtemp()) / 'ignored.json'
    core.set_ignored('_t', 'meh')
    if [x.text for x in run_check('_t', None)] != ['bad', 'fresh', 'known']: print('FAIL ignore list'); fail += 1
    core.IGNORE_FILE = real
    del CHECKS['_t']
    for n, rows in scan_all(None, pick(full=True)).items():
        c = CHECKS[n]
        print(f'{c.family:<12} {n:<32} {len(rows):4} rows, {sum(r.sev == ALERT for r in rows)} alerts, '
              f'{sum(r.sev == WARN for r in rows)} warnings{"  (slow)" if c.slow else ""}')
        for r in rows:
            if r.sev: print(f'    [{MARK[r.sev]}] {r.text}')
            if r.text.startswith('Check failed'): fail += 1
    print('self-test FAILED' if fail else 'self-test passed')
    return 1 if fail else 0


def scan(args):
    base = load_baseline()
    res = scan_all(base, pick(args.full, args.only))
    if args.json: print(json.dumps(as_json(res, base), indent=2))
    else:
        for n, rows in res.items():
            flagged = [r for r in rows if r.sev or r.new]
            print(f'{"!!" if any(r.sev == ALERT for r in rows) else "--" if flagged else "ok"}  {n} ({len(rows)})')
            for r in flagged: print(f'    [{MARK[r.sev]}] {r.text}' + (f'\n        fix: {r.fix}' if r.fix else ''))
        print(f'score {core.score(res)}/100' + ('' if base is not None else '  (no baseline yet: review, then run again with --accept)'))
    if args.accept: core.save_baseline(res); print('baseline saved', file=sys.stderr)
    return exit_code(res)


def main(argv=None):
    load_all()
    p = argparse.ArgumentParser(prog='arche-defender', description='Open-source PC security sweep. No arguments opens the window.',
                                epilog='actions: ' + '; '.join(f'{n}{" " + a.upper() if a else ""}: {h}' for n, (_, h, a) in ACTIONS.items()))
    p.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    p.add_argument('action', nargs='?', choices=list(ACTIONS), help='run one action instead of scanning')
    p.add_argument('arg', nargs='?', help='the action\'s argument')
    p.add_argument('--selftest', action='store_true', help='run every check headless and print counts')
    p.add_argument('--scan', action='store_true', help='scan headless; exit 2 on alerts, 1 on warnings or new items, else 0')
    p.add_argument('--full', action='store_true', help='with --scan: include the slow checks (malware and integrity scans)')
    p.add_argument('--json', action='store_true', help='with --scan: print JSON')
    p.add_argument('--only', action='append', metavar='CHECK', help='with --scan: run just this check (repeatable)')
    p.add_argument('--accept', action='store_true', help='with --scan: save the results as the new baseline')
    p.add_argument('--monitor', action='store_true', help='one background pass: scan and notify about new findings (the timer runs this)')
    args = p.parse_args(argv)
    if args.action:
        fn, _, argname = ACTIONS[args.action]
        if argname and not args.arg: p.error(f'{args.action} needs {argname.upper()}')
        try: print(fn(args.arg) if argname else fn())
        except ValueError as e: p.error(str(e))
        return 0
    if args.selftest: return selftest()
    if args.scan: return scan(args)
    if args.monitor:
        from .monitor import run
        return run()
    from .gui import gui
    gui()
    return 0
