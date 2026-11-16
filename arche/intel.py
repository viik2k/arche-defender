# Threat intel: public IP, domain and hash feeds cached under STATE/intel, matched offline during scans.
# Network access here happens only in actions the user runs (intel-update, password-check); scans never download anything.
import csv, hashlib, io, ipaddress, json, os, re, time, unicodedata, urllib.parse, urllib.request, zipfile
from pathlib import Path
from .core import check, action, alert, warn, item, sh, text, files, jsonf, write_private, STATE, HOME
from .browsers import copy_query
from .persistence import chromium_extensions

DIR = STATE / 'intel'
CUSTOM = Path(os.environ.get('XDG_CONFIG_HOME') or f'{HOME}/.config') / 'arche-defender' / 'iocs.txt'   # your own indicators
STALE_DAYS = 7
# name -> (url, kind). kind: ip, net (Spamhaus JSON lines), hash ('hash;comment'), domain, mixed (one IP or domain per line), url
FEEDS = {
    'Feodo Tracker': ('https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'ip'),
    'SSLBL': ('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', 'ip'),
    'ET compromised': ('https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'ip'),
    'Spamhaus DROP': ('https://www.spamhaus.org/drop/drop_v4.json', 'net'),
    'Spamhaus DROPv6': ('https://www.spamhaus.org/drop/drop_v6.json', 'net'),
    'signature-base C2': ('https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt', 'mixed'),
    'signature-base hashes': ('https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt', 'hash'),
    'HaGeZi TIF': ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt', 'domain'),
    'Electron releases': ('https://releases.electronjs.org/releases.json', 'electron'),   # not indicators: updates.py reads it
    'OpenPhish': ('https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', 'url'),   # live phishing pages
    'Malicious extensions': ('https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/Malicious-Extensions.csv', 'extid'),
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
EXT_ID = re.compile(r'(?<![a-z])[a-p]{32}(?![a-z])')


def auth_key(): return (os.environ.get('ABUSECH_AUTH_KEY') or text(KEYFILE)).strip()


def _slug(name): return re.sub(r'\W+', '-', name.lower()).strip('-') + '.txt'


ELECTRON = DIR / _slug('Electron releases')


@action('intel-update', 'Download the threat intel feeds (scans themselves never use the internet)')
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
    if kind == 'electron': return
    if kind == 'url': return out['urls'].update(dict.fromkeys((l.strip().lower().rstrip('/') for l in body.splitlines() if '://' in l), feed))
    if kind == 'extid': return out['extensions'].update(dict.fromkeys(EXT_ID.findall(body), feed))   # Chrome Web Store IDs
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
    """Indicators from every downloaded feed plus your own iocs.txt: {'ips', 'nets', 'domains', 'hashes', 'urls', 'extensions'};
    reloaded when files change."""
    srcs = [(DIR / _slug(n), k, n) for n, (_, k) in {**FEEDS, **KEYED}.items()] + [(CUSTOM, 'custom', 'your iocs.txt')]
    key = tuple(os.path.getmtime(p) if p.exists() else 0 for p, _, _ in srcs)
    if _cache.get('key') != key:
        out = {'ips': {}, 'nets': [], 'domains': {}, 'hashes': {}, 'urls': {}, 'extensions': {}}
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


@check('Malicious browser extensions', 'Threats')
def extensions():
    """Installed Chrome, Chromium, Brave, Edge and Vivaldi extensions the Chrome Web Store pulled for malware."""
    bad = load()['extensions']
    for name, title, eid, _ in chromium_extensions():
        if eid in bad: yield alert(f'{name}: {title} [{eid}] is on the list of known malicious extensions',
                                   fix='Remove it on the browser\'s extensions page, then change the passwords for sites you used while it was installed '
                                       'and sign out of them everywhere: such extensions read pages, cookies and what you type.')


def peers():
    """(process, remote ip, remote port) for every established or connecting TCP/UDP socket."""
    for l in sh('ss', '-tunpH', 'state', 'established', 'state', 'syn-sent').splitlines():
        f = l.split()
        if len(f) < 6: continue
        ip, _, port = f[5 if not f[1].isdigit() else 4].rpartition(':')   # Netid State Recv-Q Send-Q Local Peer [Process]
        m = re.search(r'\(\("([^"]+)"', l)
        yield (m[1] if m else 'a process owned by another user'), ip.strip('[]'), port


def dns_servers():
    """Resolvers in use: systemd-resolved's per-link servers and /etc/resolv.conf's, minus resolved's own stub."""
    found = {x.split('#')[0] for l in sh('resolvectl', 'dns').splitlines() for x in l.partition(': ')[2].split()}   # '#' names a DoT server
    found |= set(re.findall(r'^nameserver\s+(\S+)', text('/etc/resolv.conf'), re.M))
    return sorted(found - {'127.0.0.53', '127.0.0.54'})


@check('Known-bad connections', 'Threats')
def connections():
    """Open connections, DNS servers and /etc/hosts entries that point at addresses on a threat feed."""
    if feed_age_days() is None and not CUSTOM.exists(): return
    for proc, ip, port in peers():
        hit = ip_hit(ip)
        if hit: yield alert(f'{proc} is connected to {ip}:{port}, listed by {hit}',
                            fix=f'Find it with: ss -tunp | grep {ip}. Stop the program, quarantine its file, then run a full scan.')
    for ip in dns_servers():   # DNSChanger-style: a rogue resolver sends you to fake banking and update sites
        if hit := ip_hit(ip): yield alert(f'Your DNS server {ip} is listed by {hit}: lookups can be answered with fake sites',
                                         fix='Check the DNS setting in your network connection and in the router; set your ISP\'s or a known resolver, then change the router admin password.')
    for l in text('/etc/hosts').splitlines():
        f = l.partition('#')[0].split()
        if len(f) > 1 and (hit := ip_hit(f[0])):
            yield alert(f'/etc/hosts sends {", ".join(f[1:4])} to {f[0]}, listed by {hit}', fix='Remove that line with: sudoedit /etc/hosts')


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


def downloads(db, days=30):
    """(every URL in the redirect chain, saved file) for Chromium downloads in the last `days`. Firefox records a
    download as a history visit, so history_urls already has its URL."""
    if db.endswith('places.sqlite'): return []
    return copy_query(db, 'SELECT c.url, d.target_path FROM downloads d JOIN downloads_url_chains c ON c.id = d.id WHERE d.start_time > ?',
                      ((time.time() - days * 86400 + 11644473600) * 1e6,))


@check('Browsing history', 'Threats', slow=True)
def browsing():
    """Sites visited and files downloaded in the last 30 days that a threat feed lists as phishing, malware or C2.
    History never leaves the PC."""
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
            got = {}
            for u, path in downloads(db):   # payload URLs (URLhaus) are often never shown as a page
                if path and (hit := url_hit(u) or domain_hit(_host(u)) or ip_hit(_host(u))): got.setdefault(path, (u[:200], hit))
            for path, (u, hit) in sorted(got.items()):
                yield alert(f'{name} downloaded {os.path.basename(path)} from {u}, listed by {hit}',
                            fix=f'If it is still there, quarantine it: arche-defender quarantine "{path}". If you ran it, run a full scan and change your passwords from another device.')


SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at',
              't.ly', 'rb.gy', 'tiny.cc', 's.id', 'lnkd.in', 'qrco.de'}


def site(host):
    """The registrable name a host belongs to, roughly: paypal.com.evil.co.uk -> evil.co.uk."""
    # ponytail: no Public Suffix List; 'com.au'-style second levels are the common case it gets right
    p = host.split('.')
    return '.'.join(p[-3:] if len(p) > 2 and len(p[-1]) == 2 and p[-2] in ('com', 'co', 'net', 'org', 'gov', 'edu', 'ac') else p[-2:])


def link_signs(url):
    """(danger reasons, caution notes) for a link, without visiting it."""
    u = url.strip()
    typed = bool(re.match(r'^[a-z][\w+.-]*:(?!\d)', u, re.I))   # 'example.com:8080/x' has no scheme
    p = urllib.parse.urlsplit(u if typed else 'http://' + u)
    host, bad, careful = (p.hostname or '').rstrip('.'), [], []
    if hit := url_hit(u) or domain_hit(host) or ip_hit(host): bad.append(f'it is on a threat list ({hit})')
    if p.scheme not in ('http', 'https'): bad.append(f'it is a {p.scheme}: link, which opens or runs something instead of a web page')
    if p.username: bad.append(f'the "{p.username[:40]}@" part is decoration: the link really goes to {host}')
    if re.search(r'\.(com|net|org|gov|edu)\.(?![a-z]{2}$)', host):
        bad.append(f'the familiar name at the start is a disguise: the site is {site(host)}')
    try: shown = '.'.join(l.encode().decode('idna') if l.startswith('xn--') else l for l in host.split('.'))
    except UnicodeError: shown = host
    if not shown.isascii():
        if any(len({unicodedata.name(c, '?').split()[0] for c in l if c.isalpha()} & {'LATIN', 'CYRILLIC', 'GREEK'}) > 1 for l in shown.split('.')):
            bad.append(f'it mixes alphabets to imitate another name: it reads as {shown}')
        else: careful.append(f'it uses letters beyond plain a-z (reads as {shown}), a common way to imitate a real name')
    try: ipaddress.ip_address(host); careful.append('it points at a bare IP address, which real companies rarely link to')
    except ValueError: pass
    if host in SHORTENERS: careful.append('it is a shortened link, so the real destination is hidden until you open it')
    if typed and p.scheme == 'http': careful.append('it is not encrypted (http), so do not type passwords there')
    return bad, careful


@action('url-check', 'Check a link before you open it: threat-intel feeds and phishing tricks (offline, the link is not visited)', arg='url')
def url_check(url):
    bad, careful = link_signs(url)
    head = 'Do not open it' if bad else 'Be careful' if careful else 'No warning signs'
    out = '\n'.join([f'{head}: {url.strip()[:200]}', *(f'- {r}' for r in bad + careful)])
    if feed_age_days() is None: out += '\n(Threat feeds are not downloaded yet: run intel-update for the full check.)'
    elif not bad: out += '\n(Not on any downloaded threat list. New phishing sites appear hourly, so still check the address before signing in.)'
    return out


@action('password-check', 'Check whether a password is in known data breaches (only the first 5 characters of its SHA-1 leave this PC)', arg='password')
def password_check(pw):
    """Have I Been Pwned's k-anonymity range API: the server never sees the password or its full hash."""
    h = hashlib.sha1(pw.encode()).hexdigest().upper()
    req = urllib.request.Request(f'https://api.pwnedpasswords.com/range/{h[:5]}', headers={'User-Agent': 'arche-defender', 'Add-Padding': 'true'})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: body = r.read(4 << 20).decode('ascii', 'replace')
    except OSError as e: return f'Could not reach the breach database: {e}'
    n = next((int(c) for suf, _, c in (l.strip().partition(':') for l in body.splitlines()) if suf == h[5:] and c.isdigit()), 0)
    return (f'This password is in known breaches {n:,} times. Stop using it wherever you use it, and change it there.' if n else
            'Not in any known breach. Still use a different password for every site (a password manager makes that easy).')
