# Shared plumbing for every check module: row helpers, the check registry, safe shell/file reads, baseline diffing.
# A check module is any arche/*.py (except core/cli/gui) that registers functions with @check; cli/gui import them all.
import glob, importlib, json, os, pkgutil, re, shutil, subprocess, time
from collections import namedtuple
from pathlib import Path

HOME = str(Path.home())
STATE = Path(os.environ.get('XDG_STATE_HOME') or f'{HOME}/.local/state') / 'arche-defender'
BASE_FILE = STATE / 'baseline.json'
IGNORE_FILE = STATE / 'ignored.json'   # {check: [row text]} the user chose to hide, at any severity

# Severity: INFO rows are inventory (flagged only when new vs the baseline); WARN is weak config; ALERT is likely bad.
# A check yields (text, severity, fix) via these helpers; fix is an optional one-line "what to do about it".
INFO, WARN, ALERT = 0, 1, 2
def alert(t, fix=None): return (str(t), ALERT, fix)
def warn(t, fix=None): return (str(t), WARN, fix)
def item(t, fix=None): return (str(t), INFO, fix)
def ver(s): return re.sub(r'\d+(\.\d+){2,}', '*', s)   # app updates must not look like new items

Check = namedtuple('Check', 'family fn slow')
Row = namedtuple('Row', 'text sev new fix')
CHECKS = {}    # name -> Check; filled by @check as modules import. slow=True checks run only in a full scan.
ACTIONS = {}   # name -> (fn, help, argname or None): things that change state, run from the CLI/GUI, never during a scan


def check(name, family, slow=False):
    def reg(fn):
        CHECKS[name] = Check(family, fn, slow)
        return fn
    return reg


def action(name, help, arg=None):
    """Register `arche-defender NAME [ARG]`: fn() or fn(arg) when arg names its argument; returns a message for the user."""
    def reg(fn):
        ACTIONS[name] = (fn, help, arg)
        return fn
    return reg


def load_all():
    """Import every check module in the package, in filename order."""
    pkg = Path(__file__).parent
    for m in sorted(m.name for m in pkgutil.iter_modules([str(pkg)])):
        if m not in ('core', 'cli', 'gui', 'report'): importlib.import_module(f'{__package__}.{m}')
    return CHECKS


def sh(*cmd, err=False, timeout=30):
    try: return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT if err else subprocess.DEVNULL,
                               text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired): return ''


def have(cmd): return shutil.which(cmd) is not None


def text(p):
    try: return Path(p).read_text(errors='replace')
    except OSError: return ''


def lines(s): return [l.strip() for l in s.splitlines() if l.strip() and not l.lstrip().startswith('#')]
def files(*pats): return sorted({p for pat in pats for p in glob.glob(os.path.expanduser(pat))})


def jsonf(p):
    try: return json.loads(text(p))
    except ValueError: return {}


def write_private(p, data):
    """Write a state file only this user can read (it describes this machine)."""
    p = Path(p); p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_suffix(p.suffix + '.tmp')
    tmp.write_text(data); tmp.chmod(0o600); tmp.replace(p)


def load_baseline():
    old = Path(__file__).resolve().parent.parent / 'baseline.json'   # pre-package location, beside the launcher
    if not BASE_FILE.exists() and old.exists(): write_private(BASE_FILE, old.read_text()); old.unlink()
    return jsonf(BASE_FILE) if BASE_FILE.exists() else None


def save_baseline(results):
    """Accept these results; checks that did not run this time (slow ones after a quick scan) keep their old baseline."""
    base = load_baseline() or {}
    base.update({n: [r.text for r in rows if r.sev == INFO] for n, rows in results.items()})
    write_private(BASE_FILE, json.dumps(base, indent=2))


def run_check(name, base):
    """One check -> sorted Rows; new = an INFO row missing from the baseline (never new when there is no baseline)."""
    try: rows = list(CHECKS[name].fn())
    except Exception as e: rows = [alert(f'Check failed: {e!r}')]
    merged = {}
    for t, s, *f in rows:
        if not t: continue
        old = merged.get(t, (INFO, None))
        merged[t] = (max(old[0], int(s)), old[1] or (f[0] if f else None))
    known, skip = set((base or {}).get(name, [])), load_ignored().get(name, set())
    return [Row(t, s, base is not None and name in base and s == INFO and t not in known, f)
            for t, (s, f) in sorted(merged.items()) if t not in skip]


def load_ignored(): return {k: set(v) for k, v in (jsonf(IGNORE_FILE) if IGNORE_FILE.exists() else {}).items()}


def set_ignored(name, text, on=True):
    """Hide (or show again) one finding, keyed on check and exact text: ignoring one docker-group line hides no other line."""
    ig = load_ignored()
    (ig.setdefault(name, set()).add if on else ig.setdefault(name, set()).discard)(text)
    write_private(IGNORE_FILE, json.dumps({k: sorted(v) for k, v in ig.items() if v}, indent=1))


def _finding(arg):
    name, _, t = (arg or '').partition(': ')
    if name not in CHECKS or not t: raise ValueError(f'Give it as "Check name: finding text"; no check called {name!r}')
    return name, t


@action('ignore', 'hide one finding from now on, as "Check name: finding text" (or right-click it in the window)', arg='finding')
def _ignore(arg): set_ignored(*_finding(arg)); return f'Ignoring {arg}'


@action('unignore', 'show an ignored finding again, as "Check name: finding text"', arg='finding')
def _unignore(arg): set_ignored(*_finding(arg), on=False); return f'Showing again: {arg}'


@action('ignored', 'list the findings you chose to ignore')
def _ignored():
    ig = load_ignored()
    return '\n'.join(f'{n}: {t}' for n in sorted(ig) for t in sorted(ig[n])) or 'Nothing is ignored.'


def score(results):
    """0-100 health score for the headline: alerts cost most, weak settings less, unreviewed changes a little."""
    rows = [r for rs in results.values() for r in rs]
    return max(0, 100 - 15 * sum(r.sev == ALERT for r in rows) - 4 * sum(r.sev == WARN for r in rows) - sum(r.new for r in rows))


def stamp(): return time.strftime('%Y-%m-%d %H:%M:%S')
