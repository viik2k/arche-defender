# Vulnerable dependencies: the lockfiles of code projects in the home folder, checked against the OSV database
# (osv.dev: GitHub, PyPI, RustSec and OpenSSF malicious-package advisories). Like intel-update, the network part is an
# action the user runs (deps-update); the scan only reads its saved result.
# Only packages from the public registries are sent, so private package names never leave the PC.
import json, os, re, tomllib, urllib.request
from concurrent.futures import ThreadPoolExecutor
from .core import check, action, alert, warn, item, text, jsonf, write_private, STATE, HOME

DB = STATE / 'deps.json'
OSV = 'https://api.osv.dev/v1'
SKIP = {'node_modules', 'target', 'dist', 'build', 'venv', 'vendor', '__pycache__', 'site-packages'}
FIX = {'package-lock.json': 'npm audit fix', 'pnpm-lock.yaml': 'pnpm update', 'Cargo.lock': 'cargo update',
       'uv.lock': 'uv lock --upgrade', 'requirements.txt': 'raise the pinned versions'}
RANK = {'CRITICAL': 0, 'HIGH': 1, 'MODERATE': 2, 'MEDIUM': 2, 'LOW': 3}   # unrated counts as moderate
LEVEL = ('critical', 'high', 'moderate', 'low')


def lockfiles(root, depth=5):
    base = root.rstrip('/').count('/')
    for d, dirs, names in os.walk(root, onerror=lambda e: None):
        dirs[:] = [x for x in dirs if x not in SKIP and not x.startswith('.') and not os.path.islink(os.path.join(d, x))]
        if d.count('/') - base >= depth: dirs[:] = []
        yield from (os.path.join(d, n) for n in names if n in FIX)


def packages(path):
    """(ecosystem, name, version) of the public-registry packages a lockfile pins."""
    n, t = os.path.basename(path), text(path)
    if n == 'package-lock.json':   # lockfileVersion 2 and 3; npm 6's v1 format is not read
        try: pk = json.loads(t).get('packages') or {}
        except ValueError: return
        for k, v in pk.items():
            if 'node_modules/' in k and str(v.get('resolved', '')).startswith('https://registry.npmjs.org/') and v.get('version'):
                yield 'npm', v.get('name') or k.rsplit('node_modules/', 1)[1], v['version']
    elif n == 'pnpm-lock.yaml':   # ponytail: a private registry's packages look the same as npm's here and would be sent
        sec = re.search(r'^packages:\n(.*?)(?=^\S|\Z)', t, re.M | re.S)
        for name, ver in re.findall(r"^  '?/?((?:@[^/\s']+/)?[^@\s/'(]+)@(\d[^('\s:]*)", sec[1] if sec else '', re.M):
            yield 'npm', name, ver
    elif n in ('Cargo.lock', 'uv.lock'):
        try: pk = tomllib.loads(t).get('package', [])
        except tomllib.TOMLDecodeError: return
        for p in pk:
            src = p.get('source')
            if n == 'Cargo.lock' and isinstance(src, str) and re.search(r'crates\.io-index|index\.crates\.io', src):
                yield 'crates.io', p['name'], p['version']
            elif n == 'uv.lock' and isinstance(src, dict) and src.get('registry') == 'https://pypi.org/simple':
                yield 'PyPI', p['name'], p['version']
    elif not re.search(r'^\s*(-i|--index-url|--extra-index-url)\b', t, re.M):   # requirements.txt: pinned lines only
        for name, ver in re.findall(r'^\s*([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*==\s*([\w.]+)\s*(?:[;#]|$)', t, re.M):
            yield 'PyPI', name, ver


def osv(path, body=None):
    req = urllib.request.Request(OSV + path, data=json.dumps(body).encode() if body else None,
                                 headers={'User-Agent': 'arche-defender', 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r: return json.loads(r.read(64 << 20))


def query(pkgs):
    """{(ecosystem, name, version): [advisory ids]}, 1000 packages per request."""
    pkgs, out = sorted(pkgs), {}
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        res = osv('/querybatch', {'queries': [{'package': {'ecosystem': e, 'name': n}, 'version': v} for e, n, v in chunk]})['results']
        out |= {p: [v['id'] for v in r['vulns']] for p, r in zip(chunk, res) if r.get('vulns')}
    return out


def detail(i):
    """Severity, summary and aliases of one advisory; None for withdrawn ones and RustSec 'unmaintained' notices."""
    try: v = osv(f'/vulns/{i}')
    except (OSError, ValueError): return {'sev': '?', 'summary': '', 'aliases': [], 'err': 1}   # asked again next time
    ds = v.get('database_specific') or {}
    if v.get('withdrawn') or ds.get('informational'): return None
    return {'sev': str(ds.get('severity') or '?').upper(), 'summary': (v.get('summary') or '')[:120], 'aliases': v.get('aliases') or []}


@action('deps-update', 'Check your code projects\' dependencies for known vulnerabilities and malicious packages '
                       '(sends public package names and versions to osv.dev)')
def update():
    locks = {p: sorted(set(packages(p))) for p in lockfiles(HOME)}
    locks = {p: v for p, v in locks.items() if v}
    if not locks: return 'No npm, pnpm, Cargo, uv or requirements.txt lockfiles found in your home folder.'
    try:
        hits = query({x for v in locks.values() for x in v})
        old = {k: v for k, v in jsonf(DB).get('details', {}).items() if not (v or {}).get('err')}   # advisories rarely change
        new = sorted({i for v in hits.values() for i in v} - old.keys())
        with ThreadPoolExecutor(16) as ex: det = old | dict(zip(new, ex.map(detail, new)))
    except (OSError, ValueError, KeyError) as e: return f'Could not reach the OSV database ({type(e).__name__}); nothing changed.'
    db = {'details': det, 'lockfiles': {p: {'mtime': os.stat(p).st_mtime, 'vulns': [[*k, hits[k]] for k in v if k in hits]}
                                        for p, v in locks.items()}}
    write_private(DB, json.dumps(db))
    n = sum(bool(l['vulns']) for l in db['lockfiles'].values())
    return f'Checked {len({x for v in locks.values() for x in v})} packages in {len(locks)} lockfiles; {n} have known advisories. Run a scan to see them.'


def triage(vulns, det):
    """(malicious packages, {'name version': (worst rank, advisory ids)}) for one lockfile."""
    bad, worst = [], {}
    for eco, name, ver, ids in vulns:
        ids = [i for i in ids if det.get(i)]
        ids = [i for i in ids if i.startswith('GHSA') or not set(det[i]['aliases']) & set(ids)]   # one entry per advisory, GitHub's has the severity
        if any(i.startswith('MAL-') for i in ids): bad.append(f'{name} {ver} ({eco})')
        elif ids: worst[f'{name} {ver}'] = (min(RANK.get(det[i]['sev'], 2) for i in ids), ids)
    return bad, worst


def rows(locks, det):
    """locks: {lockfile: [[ecosystem, name, version, ids]]}. One summary warning, so a developer's many projects
    do not swamp the score; each lockfile is an item with what to update."""
    crit = 0
    for path, vulns in locks.items():
        where, fix = path.replace(HOME, '~'), FIX.get(os.path.basename(path), 'update them')
        bad, worst = triage(vulns, det)
        for b in bad: yield alert(f'{where} pins {b}, a known malicious package',
                                  fix='Remove it and reinstall from a clean lockfile. Install scripts may already have run, so change the passwords and tokens this PC holds.')
        if not worst: continue
        top = sorted(worst, key=lambda k: (worst[k][0], k))
        crit += worst[top[0]][0] == 0
        yield item(f'{where}: dependencies with {LEVEL[worst[top[0]][0]]} vulnerabilities',
                   fix=f'Update them ({fix}), then run deps-update again: ' + ', '.join(f'{k} ({LEVEL[worst[k][0]]}, {worst[k][1][0]})' for k in top[:5]) +
                       (f' and {len(top) - 5} more' if len(top) > 5 else '') + '. Details on osv.dev.')
    if crit: yield warn(f'{crit} of your code projects pin dependencies with critical vulnerabilities',
                        fix='Each lockfile is listed in this check with what to update. They matter most for projects you run as servers or ship to others.')


@check('Vulnerable dependencies', 'Updates')
def dependencies():
    """Known vulnerabilities and malicious packages in your projects' lockfiles, from the last deps-update."""
    db = jsonf(DB)
    if not db:
        yield item('Dependency check has not run', fix='Run: arche-defender deps-update (checks your code projects against the OSV vulnerability database).')
        return
    def current(p, l):
        try: return os.stat(p).st_mtime == l['mtime']   # ponytail: a lockfile changed since the check waits for the next deps-update
        except OSError: return False
    yield from rows({p: l['vulns'] for p, l in db.get('lockfiles', {}).items() if current(p, l)}, db.get('details', {}))
