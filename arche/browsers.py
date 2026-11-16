# Browsers: protection switched off (Safe Browsing), saved passwords and cookies kept under Chromium's built-in key,
# managed policies that force extensions, proxies or search engines (how adware persists), and the root
# certificates trusted beyond the OS bundle (an added root can read all HTTPS traffic).
# Also browsers started with flags that hand over cookies or weaken HTTPS, and Firefox security prefs turned down.
# Which extensions are installed is persistence.py's 'Browser extensions'; --no-sandbox is hardening.py's 'App sandboxes'.
import json, os, re, shlex, shutil, sqlite3, tempfile
from pathlib import Path
from .core import check, alert, warn, item, sh, have, text, files, jsonf, HOME
from .persistence import CHROMIUM, chromium_roots
from .hardening import argv

FIREFOX = [f'{HOME}/.mozilla/firefox', f'{HOME}/.config/mozilla/firefox', f'{HOME}/.var/app/org.mozilla.firefox/.mozilla/firefox']


def copy_query(db, sql, args=()):
    """Rows from a copy of a browser SQLite file (the live one is locked while the browser runs); [] on any error."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cp = Path(tmp) / 'db.sqlite'; shutil.copyfile(db, cp)
            if os.path.exists(f'{db}-wal'): shutil.copyfile(f'{db}-wal', f'{cp}-wal')   # recent rows not yet merged in (Firefox, KDE)
            con = sqlite3.connect(cp)   # a writable copy, so SQLite can read the WAL without its -shm index
            try: return con.execute(sql, args).fetchall()
            finally: con.close()
    except (OSError, sqlite3.Error): return []


def chromium_profiles():
    """(browser, profile folder) for every Chromium-family profile, native and Flatpak."""
    for name, sub, flat in CHROMIUM:
        for root in (f'{HOME}/.config/{sub}', f'{HOME}/.var/app/{flat}/config/{sub}'):
            for prefs in files(f'{root}/*/Preferences'): yield name, os.path.dirname(prefs)


def label(name, prof): return f'{name}' + ('' if os.path.basename(prof) == 'Default' else f' ({os.path.basename(prof)})')


def firefox_prefs(prof):
    """user_pref values from prefs.js and user.js (user.js wins, as in Firefox)."""
    out = {}
    for f in ('prefs.js', 'user.js'):
        for k, v in re.findall(r'^user_pref\("([^"]+)",\s*(.+?)\);', text(f'{prof}/{f}'), re.M):
            try: out[k] = json.loads(v)
            except ValueError: out[k] = v
    return out


@check('Browser protection', 'Browsers')
def protection():
    """Safe Browsing (blocks known phishing and malware sites), weakly stored saved passwords, and proxies set inside Firefox."""
    for name, prof in chromium_profiles():
        sb = jsonf(f'{prof}/Preferences').get('safebrowsing') or {}
        if sb.get('enabled') is False:
            yield warn(f'{label(name, prof)}: Safe Browsing is off', fix='Settings > Privacy and security > Security: choose Standard or Enhanced protection.')
        # v10 = encrypted with the fixed key Chromium uses when no keyring is available: any program (or a copied disk) can read them.
        n = (copy_query(f'{prof}/Login Data', "SELECT count(*) FROM logins WHERE CAST(substr(password_value, 1, 3) AS TEXT) = 'v10'") or [(0,)])[0][0]
        c = copy_query(f'{prof}/Cookies', "SELECT 1 FROM cookies WHERE CAST(substr(encrypted_value, 1, 3) AS TEXT) = 'v10' LIMIT 1")
        if n or c:   # cookies: an infostealer replays them to be signed in as you, past passwords and 2FA
            what = ' and '.join([f'{n} saved passwords'] * bool(n) + ['its sign-in cookies'] * bool(c))
            yield warn(f'{label(name, prof)}: {what} are protected only by a built-in key',
                       fix='Start the browser with --password-store=kwallet6 (KDE) or gnome-libsecret so the keyring protects them '
                           '(a Flatpak browser needs access to org.freedesktop.secrets), and keep passwords in a password manager.')
    for prof in sorted({os.path.dirname(p) for r in FIREFOX for p in files(f'{r}/*/prefs.js')}):
        p, name = firefox_prefs(prof), f'Firefox ({os.path.basename(prof).partition(".")[2] or os.path.basename(prof)})'
        off = [k.split('.')[-2] for k in ('browser.safebrowsing.malware.enabled', 'browser.safebrowsing.phishing.enabled',
                                          'browser.safebrowsing.downloads.enabled') if p.get(k) is False]
        if off: yield warn(f'{name}: Safe Browsing {" and ".join(off)} protection is off',
                           fix='Settings > Privacy & Security > Security: tick "Block dangerous and deceptive content".')
        if p.get('network.proxy.type') in (1, 2):
            where = p.get('network.proxy.autoconfig_url') or ', '.join(f'{p[k]}:{p.get(k + "_port", "")}' for k in ('network.proxy.http', 'network.proxy.socks') if p.get(k))
            yield item(f'{name}: sends traffic through a proxy ({where})', fix='Settings > General > Network Settings. Remove it unless you set it up.')
        for k, bad, what in FF_WEAK:
            if k in p and bad(p[k]): yield warn(f'{name} {what} ({k} = {json.dumps(p[k])})',
                                               fix=f'In about:config, reset {k} (and remove it from user.js in {prof.replace(HOME, "~")} if it is there).')


FF_WEAK = (('xpinstall.signatures.required', lambda v: v is False, 'installs extensions without Mozilla\'s signature check'),
           ('security.tls.version.min', lambda v: isinstance(v, int) and v < 3, 'allows outdated TLS 1.0/1.1 connections'),
           ('security.cert_pinning.enforcement_level', lambda v: v == 0, 'has certificate pinning off'),
           ('security.mixed_content.block_active_content', lambda v: v is False, 'runs insecure scripts on secure pages'),
           ('network.stricttransportsecurity.preloadlist', lambda v: v is False, 'ignores the HSTS preload list'))

LAUNCH_FLAGS = {
    '--remote-debugging-port': 'remote debugging on your real profile: any program on this PC can read its cookies and logins (cookie stealers do this)',
    '--remote-debugging-pipe': 'remote debugging on your real profile: any program on this PC can read its cookies and logins (cookie stealers do this)',
    '--load-extension': 'an extension loaded from a folder, outside the store',
    '--ignore-certificate-errors': 'certificate errors ignored, so HTTPS traffic can be intercepted',
    '--proxy-server': 'a proxy for all browsing', '--proxy-pac-url': 'a proxy for all browsing'}
BROWSER_EXE = re.compile(r'(^|/)(chrome|chromium|chromium-browser|google-chrome(-stable)?|brave|brave-browser(-stable)?|msedge|microsoft-edge(-stable)?|vivaldi(-bin|-stable)?|helium)$')


def launch_flags(args):
    """(flag, why) for each risky flag. Remote debugging counts only on a real profile: test and debug tools
    (Playwright, Puppeteer, VS Code) give the browser a throwaway --user-data-dir."""
    udd = next((a.split('=', 1)[1] for a in args if a.startswith('--user-data-dir=')), '')
    real = not udd or os.path.realpath(os.path.expanduser(udd)) in {os.path.realpath(r) for _, r in chromium_roots()}
    for f in dict.fromkeys(a.split('=', 1)[0] for a in args):
        if f in LAUNCH_FLAGS and (real or not f.startswith('--remote-debugging')): yield f, LAUNCH_FLAGS[f]


def flag_row(where, f, why, fix):
    return (item if f.startswith('--proxy') else warn)(f'{where} with {f}: {why}', fix=fix)


@check('Browser launch flags', 'Browsers')
def flags():
    """Chromium-family browsers started (now, by a launcher, or by a *-flags.conf file) with flags that leak cookies or weaken HTTPS."""
    running = set()
    for pid in filter(str.isdigit, os.listdir('/proc')):
        a = argv(pid)
        if a and BROWSER_EXE.search(a[0]) and not any(x.startswith('--type=') for x in a):
            running |= {(os.path.basename(a[0]), f, why) for f, why in launch_flags(a)}
    for exe, f, why in sorted(running):
        yield flag_row(f'{exe} is running', f, why, 'If you did not start it this way (a developer tool or test), close the browser, '
                                                    'check its launchers and Startup entries, and sign out of important sites everywhere.')
    for conf in files(f'{HOME}/.config/*-flags.conf'):
        args = [a for l in text(conf).splitlines() if not l.lstrip().startswith('#') for a in l.split()]
        for f, why in launch_flags(args): yield flag_row(f'{conf.replace(HOME, "~")} starts the browser', f, why, f'Remove {f} from {conf} unless you added it.')
    for d in files(f'{HOME}/.local/share/applications/*.desktop', f'{HOME}/.config/autostart/*.desktop', f'{HOME}/Desktop/*.desktop'):
        for ex in re.findall(r'^Exec=(.+)$', text(d), re.M):
            try: args = shlex.split(ex)
            except ValueError: continue
            if not any(BROWSER_EXE.search(a) or a in {fl for _, _, fl in CHROMIUM} for a in args[:4]): continue   # also `flatpak run <id>`
            for f, why in launch_flags(args): yield flag_row(f'Launcher {d.replace(HOME, "~")} starts a browser', f, why,
                                                             f'Remove {f} from its Exec= line, or delete {d} if you did not make it (malware edits launchers this way).')


CHROMIUM_POLICY_DIRS = {'Chrome': '/etc/opt/chrome/policies', 'Chromium': '/etc/chromium/policies', 'Brave': '/etc/brave/policies',
                        'Edge': '/etc/opt/edge/policies', 'Vivaldi': '/etc/opt/vivaldi/policies'}
FIREFOX_POLICIES = ('/etc/firefox/policies/policies.json', '/usr/lib64/firefox/distribution/policies.json',
                    '/usr/lib/firefox/distribution/policies.json', '/usr/lib64/firefox-esr/distribution/policies.json')
RISKY_POLICY = {   # policy name -> what it lets whoever wrote it do
    'ExtensionInstallForcelist': 'forces extensions you cannot remove', 'ExtensionSettings': 'controls which extensions are installed',
    'Extensions': 'forces extensions you cannot remove', 'ProxySettings': 'routes browsing through a proxy',
    'ProxyServer': 'routes browsing through a proxy', 'ProxyMode': 'routes browsing through a proxy', 'ProxyPacUrl': 'routes browsing through a proxy',
    'Proxy': 'routes browsing through a proxy', 'DefaultSearchProviderSearchURL': 'sets the search engine', 'SearchEngines': 'sets the search engine',
    'HomepageLocation': 'sets the home page', 'Homepage': 'sets the home page', 'RestoreOnStartupURLs': 'opens pages at startup',
    'Certificates': 'can add trusted root certificates', 'SafeBrowsingProtectionLevel': 'changes Safe Browsing',
    'SafeBrowsingEnabled': 'changes Safe Browsing', 'DisableSecurityBypass': 'changes security warnings',
    'CertificateTransparencyEnforcementDisabledForUrls': 'turns off certificate checks for some sites'}


def policy_rows(browser, path, policies):
    for k, v in sorted(policies.items()):
        if k in RISKY_POLICY:
            yield warn(f'{browser} policy {k} {RISKY_POLICY[k]}: {json.dumps(v)[:160]}',
                       fix=f'Unless your employer manages this PC, delete the policy in {path} (needs sudo) and check Startup entries.')
        else: yield item(f'{browser} policy {k}')


@check('Browser policies', 'Browsers')
def policies():
    """Enterprise policies on a home PC: adware and hijackers use them to force extensions, proxies and search engines."""
    for browser, d in CHROMIUM_POLICY_DIRS.items():
        for f in files(f'{d}/managed/*.json', f'{d}/recommended/*.json'): yield from policy_rows(browser, f, jsonf(f))
    for f in files(*FIREFOX_POLICIES): yield from policy_rows('Firefox', f, jsonf(f).get('policies') or {})


def subject(pem):
    s = sh('openssl', 'x509', '-noout', '-subject', '-in', pem).strip()
    return (re.search(r'CN\s*=\s*([^,/]+)', s) or re.search(r'O\s*=\s*([^,/]+)', s) or [None, os.path.basename(pem)])[1].strip()


def nss_cas(db):
    """Nicknames of certificates an NSS database trusts as a CA for websites (trust flags with C in the SSL field)."""
    return [n.strip() for n, ssl in re.findall(r'^(.+?)\s{2,}([A-Za-z]*),[A-Za-z]*,[A-Za-z]*[ \t]*$', sh('certutil', '-L', '-d', f'sql:{db}', timeout=15), re.M) if 'C' in ssl]


@check('Trusted certificates', 'Network')
def certificates():
    """Root certificates added on top of the OS bundle: a rogue one lets its owner read and change all HTTPS traffic."""
    for f in files('/etc/pki/ca-trust/source/anchors/*', '/usr/local/share/ca-certificates/*', '/etc/ca-certificates/trust-source/anchors/*'):
        yield item(f'System-wide trusted root: {subject(f)} ({f})', fix='Added with root rights. Remove it and run update-ca-trust if you do not recognise it.')
    if not have('certutil'): return
    # ponytail: user-level NSS stores need no root to change, so a root there is a warning; system anchors are inventory.
    for db in [f'{HOME}/.pki/nssdb'] + [os.path.dirname(p) for r in FIREFOX for p in files(f'{r}/*/cert9.db')]:
        if not os.path.exists(f'{db}/cert9.db'): continue
        for n in nss_cas(db):
            yield warn(f'Root certificate "{n}" is trusted for websites in {db.replace(HOME, "~")}',
                       fix=f'Remove it unless you added it: certutil -D -d sql:{db} -n "{n}" (Firefox: Settings > Certificates).')
