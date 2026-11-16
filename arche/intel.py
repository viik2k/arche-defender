# Threat intel: public IP, domain and hash feeds cached under STATE/intel, matched offline during scans.
# The only network access in the tool is intel-update, which the user runs; scans never download anything.
import csv, io, ipaddress, json, os, re, time, urllib.request, zipfile
from pathlib import Path
from .core import check, action, alert, warn, item, sh, text, files, jsonf, write_private, STATE, HOME
from .browsers import copy_query

DIR = STATE / 'intel'
CUSTOM = Path(os.environ.get('XDG_CONFIG_HOME') or f'{HOME}/.config') / 'arche-defender' / 'iocs.txt'   # your own indicators
STALE_DAYS = 7
# name -> (url, kind). kind: ip, net (Spamhaus JSON lines), hash ('hash;comment'), domain, mixed (one IP or domain per line)
FEEDS = {
    'Feodo Tracker': ('https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'ip'),
    'SSLBL': ('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', 'ip'),
    'ET compromised': ('https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'ip'),
    'Spamhaus DROP': ('https://www.spamhaus.org/drop/drop_v4.json', 'net'),
    'Spamhaus DROPv6': ('https://www.spamhaus.org/drop/drop_v6.json', 'net'),
    'signature-base C2': ('https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt', 'mixed'),
    'signature-base hashes': ('https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt', 'hash'),
    'HaGeZi TIF': ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt', 'domain'),
}
KEYFILE = CUSTOM.parent / 'abusech.key'
# Need a free abuse.ch Auth-Key (https://auth.abuse.ch/) in KEYFILE or $ABUSECH_AUTH_KEY; it goes in the URL path.
# ponytail: CSV columns are read from the '#' header row, since the formats are only documented behind a login.
KEYED = {
    'URLhaus': ('https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv', 'abusech'),
    'MalwareBazaar': ('https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv', 'abusech'),
    'ThreatFox': ('https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip', 'abusech'),
}
HASH = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
DOMAIN = re.compile(r'^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$')


def auth_key(): return (os.environ.get('ABUSECH_AUTH_KEY') or text(KEYFILE)).strip()


def _slug(name): return re.sub(r'\W+', '-', name.lower()).strip('-') + '.txt'


@action('intel-update', 'Download the threat intel feeds (the only time Arche Defender uses the network)')
def update():
    got, failed, key = [], [], auth_key()
    feeds = {**FEEDS, **({n: (u.format(key=urllib.request.quote(key, safe='')), k) for n, (u, k) in KEYED.items()} if key else {})}
    for name, (url, _) in feeds.items():
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'arche-defender'})
            with urllib.request.urlopen(req, timeout=60) as r: data = r.read(64 << 20)   # ponytail: 64 MB cap per feed
            if data[:2] == b'PK':
                with zipfile.ZipFile(io.BytesIO(data)) as z, z.open(z.namelist()[0]) as f: data = f.read(256 << 20)
            write_private(DIR / _slug(name), data.decode('utf-8', 'replace')); got.append(name)
        except (OSError, zipfile.BadZipFile, IndexError) as e: failed.append(f'{name} ({str(e).replace(key, "***") if key else e})')
    _cache.clear()
    return f'Updated {len(got)} feeds, {sum(map(len, load().values()))} indicators.' + (f' Failed: {"; ".join(failed)}' if failed else '')


def _host(url): return re.sub(r'^[a-z][\w+.-]*://([^/:?#@]*@)?(\[[^\]]+\]|[^/:?#]+).*$', r'\2', url.strip(), flags=re.I | re.S).strip('[]').lower()


def _abusech(body, feed, out):
    """URLhaus, MalwareBazaar and ThreatFox CSV: columns come from the last '#' comment row with several fields."""
    cols = None
    for row in csv.reader(io.StringIO(body), skipinitialspace=True):
        if not row: continue
        if row[0].lstrip().startswith('#'):
            if len(row) > 3: cols = [c.strip(' #"').lower() for c in row]
            continue
        if not cols or len(row) != len(cols): continue
        r = dict(zip(cols, (c.strip() for c in row)))
        name = r.get('signature') or r.get('malware_printable') or r.get('threat') or ''
        label = f'{feed}: {name}' if name and name.lower() not in ('n/a', 'none', 'unknown') else feed
        for h in ('sha256_hash', 'sha1_hash', 'md5_hash'):
            if HASH.match(r.get(h, '')): out['hashes'][r[h].lower()] = label
        t, v = r.get('ioc_type', 'url' if 'url' in r else ''), r.get('ioc_value') or r.get('url', '')
        if t.endswith('_hash') and HASH.match(v): out['hashes'][v.lower()] = label
        elif t == 'domain' and DOMAIN.match(v.lower()): out['domains'][v.lower()] = label
        elif t == 'ip:port' or t == 'url':
            if t == 'url': out['urls'][v.lower().rstrip('/')] = label   # URL only: payloads often sit on github.com and the like
            try: out['ips'][str(ipaddress.ip_address(v.rpartition(':')[0] if t == 'ip:port' else _host(v)))] = label
            except ValueError: pass


def _parse(kind, body, feed, out):
    if kind == 'abusech': return _abusech(body, feed, out)
    for raw in body.splitlines():
        l = raw.strip()
        if not l or l[0] in '#;!/': continue
        if kind == 'net':
            try: out['nets'].append((ipaddress.ip_network(json.loads(l)['cidr']), feed))
            except (ValueError, KeyError, TypeError): pass
            continue
        val, _, note = l.partition(';')
        val = val.split()[0].strip().lower() if val.split() else ''
        label = f'{feed}: {note.strip()}' if note.strip() else feed
        if HASH.match(val): out['hashes'][val] = label
        elif kind in ('ip', 'mixed') or kind == 'custom':
            try: out['ips'][str(ipaddress.ip_address(val))] = label; continue
            except ValueError: pass
            if '/' in val:
                try: out['nets'].append((ipaddress.ip_network(val, strict=False), label)); continue
                except ValueError: pass
            if DOMAIN.match(val): out['domains'][val] = label
        elif kind == 'domain' and DOMAIN.match(val.lstrip('*.')): out['domains'][val.lstrip('*.')] = label


_cache = {}


def load():
    """Indicators from every downloaded feed plus your own iocs.txt: {'ips', 'nets', 'domains', 'hashes'}; reloaded when files change."""
    srcs = [(DIR / _slug(n), k, n) for n, (_, k) in {**FEEDS, **KEYED}.items()] + [(CUSTOM, 'custom', 'your iocs.txt')]
    key = tuple(os.path.getmtime(p) if p.exists() else 0 for p, _, _ in srcs)
    if _cache.get('key') != key:
        out = {'ips': {}, 'nets': [], 'domains': {}, 'hashes': {}, 'urls': {}}
        for p, kind, name in srcs: _parse(kind, text(p), name, out)
        _cache.update(key=key, data=out)
    return _cache['data']


def ip_hit(ip):
    try: a = ipaddress.ip_address(str(ip).strip('[]').split('%')[0])
    except ValueError: return None
    if not a.is_global: return None
    i = load()
    return i['ips'].get(str(a)) or next((f for n, f in i['nets'] if a.version == n.version and a in n), None)


def domain_hit(host):
    """The domain or any parent domain (evil.example.com -> example.com) on a feed."""
    parts, d = (host or '').lower().strip('.').split('.'), load()['domains']
    return next((d[x] for x in ('.'.join(parts[i:]) for i in range(len(parts) - 1)) if x in d), None)


def url_hit(url): return load().get('urls', {}).get((url or '').lower().rstrip('/'))


def hash_hit(*digests): return next((load()['hashes'][h.lower()] for h in digests if h and h.lower() in load()['hashes']), None)


def feed_age_days():
    ages = [time.time() - os.path.getmtime(p) for p in (DIR / _slug(n) for n in (*FEEDS, *KEYED)) if p.exists()]
    return int(min(ages) / 86400) if ages else None


@check('Threat intel', 'Threats')
def status():
    age = feed_age_days()
    if age is None: yield warn('Threat intel feeds have never been downloaded, so connections, files and history are not checked against them',
                               fix='Run: arche-defender intel-update (or Tools > intel-update in the app)')
    elif age > STALE_DAYS: yield warn(f'Threat intel feeds are {age} days old', fix='Run: arche-defender intel-update')
    if not auth_key(): yield item('abuse.ch feeds (URLhaus, MalwareBazaar, ThreatFox) are off',
                                  fix=f'Get a free Auth-Key at https://auth.abuse.ch/, save it in {KEYFILE} (chmod 600), then run intel-update.')


def peers():
    """(process, remote ip, remote port) for every established or connecting TCP/UDP socket."""
    for l in sh('ss', '-tunpH', 'state', 'established', 'state', 'syn-sent').splitlines():
        f = l.split()
        if len(f) < 6: continue
        ip, _, port = f[5 if not f[1].isdigit() else 4].rpartition(':')   # Netid State Recv-Q Send-Q Local Peer [Process]
        m = re.search(r'\(\("([^"]+)"', l)
        yield (m[1] if m else 'a process owned by another user'), ip.strip('[]'), port


@check('Known-bad connections', 'Threats')
def connections():
    if feed_age_days() is None and not CUSTOM.exists(): return
    for proc, ip, port in peers():
        hit = ip_hit(ip)
        if hit: yield alert(f'{proc} is connected to {ip}:{port}, listed by {hit}',
                            fix=f'Find it with: ss -tunp | grep {ip}. Stop the program, quarantine its file, then run a full scan.')


BROWSERS = {   # name -> globs of Chromium History or Firefox places.sqlite files (native and Flatpak)
    'Chrome': ['~/.config/google-chrome/*/History', '~/.var/app/com.google.Chrome/config/google-chrome/*/History'],
    'Chromium': ['~/.config/chromium/*/History', '~/.var/app/org.chromium.Chromium/config/chromium/*/History'],
    'Edge': ['~/.config/microsoft-edge/*/History', '~/.var/app/com.microsoft.Edge/config/microsoft-edge/*/History'],
    'Brave': ['~/.config/BraveSoftware/Brave-Browser/*/History', '~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/*/History'],
    'Vivaldi': ['~/.config/vivaldi/*/History', '~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/*/History'],
    'Helium': ['~/.config/net.imput.helium/*/History'],
    'Firefox': ['~/.mozilla/firefox/*/places.sqlite', '~/.config/mozilla/firefox/*/places.sqlite',
                '~/.var/app/org.mozilla.firefox/.mozilla/firefox/*/places.sqlite'],
}


def history_urls(db, days=30):
    """URLs visited in the last `days`."""
    if db.endswith('places.sqlite'):
        q, since = 'SELECT url FROM moz_places WHERE last_visit_date > ?', (time.time() - days * 86400) * 1e6
    else:   # Chromium stores microseconds since 1601
        q, since = 'SELECT url FROM urls WHERE last_visit_time > ?', (time.time() - days * 86400 + 11644473600) * 1e6
    return {u for (u,) in copy_query(db, q, (since,)) if '://' in u}


@check('Browsing history', 'Threats', slow=True)
def browsing():
    """Sites visited in the last 30 days that a threat feed lists as phishing, malware or C2. History never leaves the PC."""
    if feed_age_days() is None and not CUSTOM.exists(): return
    for name, pats in BROWSERS.items():
        for db in files(*pats):
            hits = {}
            for u in history_urls(db):
                host = _host(u)
                if hit := url_hit(u): hits.setdefault(u[:200], hit)   # the exact page, when only that URL is listed
                elif hit := domain_hit(host) or ip_hit(host): hits.setdefault(host, hit)
            for where, hit in sorted(hits.items()):
                yield alert(f'{name} visited {where} in the last 30 days, listed by {hit}',
                            fix='If you entered a password there, change it. Run a full scan, and check Browser extensions.')
