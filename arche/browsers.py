# Browsers: protection switched off (Safe Browsing), saved passwords and cookies kept under Chromium's built-in key,
# managed policies that force extensions, proxies or search engines (how adware persists), and the root
# certificates trusted beyond the OS bundle (an added root can read all HTTPS traffic).
# Also browsers started with flags that hand over cookies or weaken HTTPS, and Firefox security prefs turned down.
# Which extensions are installed is persistence.py's 'Browser extensions'; --no-sandbox is hardening.py's 'App sandboxes'.
import base64, json, os, re, shlex, shutil, sqlite3, tempfile, urllib.parse
from pathlib import Path
from .core import check, alert, warn, item, sh, have, text, files, jsonf, HOME
from .persistence import CHROMIUM, chromium_roots, chromium_extensions
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
    for name, root in chromium_roots():
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


def in_repo(p):
    while p not in ('/', HOME, ''):
        if os.path.exists(f'{p}/.git'): return True
        p = os.path.dirname(p)
    return False


def unpacked_rows(name, prof):
    """Extensions loaded from a folder (developer mode, location 4, or --load-extension, location 8): they are not under
    Extensions/, so the inventory and the malicious-ID feed never see them, and store review never did."""
    settings = {}   # Chrome can keep them in Secure Preferences, Brave and others in Preferences
    for f in ('Preferences', 'Secure Preferences'): settings.update((jsonf(f'{prof}/{f}').get('extensions') or {}).get('settings') or {})
    for eid, v in settings.items():
        if not isinstance(v, dict) or v.get('location') not in (4, 8) or not os.path.isdir(path := v.get('path') or ''): continue
        title = (v.get('manifest') or jsonf(f'{path}/manifest.json')).get('name') or eid
        if os.access(path, os.W_OK) and not in_repo(path):
            yield warn(f'{label(name, prof)}: extension "{title}" is loaded from a folder, not from the store: {path.replace(HOME, "~")}',
                       fix='No store review ever saw it, and malware installs extensions this way to read your pages. If you did not '
                           'load it yourself: remove it on the browser\'s extensions page, then delete the folder.')
        else: yield item(f'{label(name, prof)}: extension "{title}" is loaded from {path.replace(HOME, "~")}' + (' (your own project)' if in_repo(path) else ''))


@check('Browser protection', 'Browsers')
def protection():
    """Safe Browsing (blocks known phishing and malware sites), weakly stored saved passwords, proxies set inside Firefox,
    and extensions loaded from a folder instead of the store."""
    for name, prof in chromium_profiles():
        yield from unpacked_rows(name, prof)
        sb = jsonf(f'{prof}/Preferences').get('safebrowsing') or {}
        if sb.get('enabled') is False:
            yield warn(f'{label(name, prof)}: Safe Browsing is off', fix='Settings > Privacy and security > Security: choose Standard or Enhanced protection.')
        # v10 = encrypted with the fixed key Chromium uses when no keyring is available: any program (or a copied disk) can read them.
        n = (copy_query(f'{prof}/Login Data', "SELECT count(*) FROM logins WHERE CAST(substr(password_value, 1, 3) AS TEXT) = 'v10'") or [(0,)])[0][0]
        c = copy_query(f'{prof}/Cookies', "SELECT 1 FROM cookies WHERE CAST(substr(encrypted_value, 1, 3) AS TEXT) = 'v10' LIMIT 1")
        k = (copy_query(f'{prof}/Web Data', "SELECT count(*) FROM credit_cards WHERE CAST(substr(card_number_encrypted, 1, 3) AS TEXT) = 'v10'") or [(0,)])[0][0]
        if n or c or k:   # cookies: an infostealer replays them to be signed in as you, past passwords and 2FA
            what = [f'{n} saved password{"s" * (n > 1)}'] * bool(n) + ['its sign-in cookies'] * bool(c) + [f'{k} saved payment card{"s" * (k > 1)}'] * bool(k)
            what = ', '.join(what[:-1]) + ' and ' * (len(what) > 1) + what[-1]
            yield warn(f'{label(name, prof)}: {what} are protected only by a built-in key',
                       fix='Start the browser with --password-store=kwallet6 (KDE) or gnome-libsecret so the keyring protects them '
                           '(a Flatpak browser needs access to org.freedesktop.secrets), and keep passwords in a password manager.')
        # Password Checkup's own findings, kept beside the passwords: 0 = in a data breach, 1 = typed into a phishing site
        for t, k in copy_query(f'{prof}/Login Data', 'SELECT insecurity_type, count(*) FROM insecure_credentials '
                                                     'WHERE is_muted = 0 AND insecurity_type IN (0, 1) GROUP BY 1'):
            yield (warn, alert)[t](f'{label(name, prof)}: {k} saved password{"s were" if k > 1 else " was"} {("found in a data breach", "entered on a phishing site")[t]}',
                                   fix='Change them now, and anywhere you reused them. Password Manager > Checkup lists them.')
    for prof in sorted({os.path.dirname(p) for r in FIREFOX for p in files(f'{r}/*/prefs.js')}):
        p, name = firefox_prefs(prof), f'Firefox ({os.path.basename(prof).partition(".")[2] or os.path.basename(prof)})'
        off = [k.split('.')[-2] for k in ('browser.safebrowsing.malware.enabled', 'browser.safebrowsing.phishing.enabled',
                                          'browser.safebrowsing.downloads.enabled') if p.get(k) is False]
        if off: yield warn(f'{name}: Safe Browsing {" and ".join(off)} protection is off',
                           fix='Settings > Privacy & Security > Security: tick "Block dangerous and deceptive content".')
        if p.get('network.proxy.type') in (1, 2):
            where = p.get('network.proxy.autoconfig_url') or ', '.join(f'{p[k]}:{p.get(k + "_port", "")}' for k in ('network.proxy.http', 'network.proxy.socks') if p.get(k))
            yield item(f'{name}: sends traffic through a proxy ({where})', fix='Settings > General > Network Settings. Remove it unless you set it up.')
        n = len(jsonf(f'{prof}/logins.json').get('logins') or [])
        if n and no_primary_password(f'{prof}/key4.db'):   # infostealers decrypt these with no password, like Chromium's v10
            yield warn(f'{name}: {n} saved passwords are not protected by a Primary Password',
                       fix='Settings > Privacy & Security > Passwords: tick "Use a Primary Password", or keep passwords in a password manager.')
        for k, bad, what in FF_WEAK:
            if k in p and bad(p[k]): yield warn(f'{name} {what} ({k} = {json.dumps(p[k])})',
                                               fix=f'In about:config, reset {k} (and remove it from user.js in {prof.replace(HOME, "~")} if it is there).')


PBKDF2 = bytes.fromhex('06092a864886f70d01050c')   # DER of OID 1.2.840.113549.1.5.12


def der(b):
    """(value, rest) of the DER element at the start of b."""
    n, h = b[1], 2
    if n & 0x80: h, n = 2 + (n & 0x7f), int.from_bytes(b[2:2 + (n & 0x7f)], 'big')
    return b[h:h + n], b[h + n:]


def no_primary_password(key4):
    """Whether Firefox's key store has no Primary Password: NSS then derives its key with 1 PBKDF2 round, not 10000
    (checked against key4.db files certutil made). None when unknown: no key4.db, or the pre-2020 3DES format."""
    row = copy_query(key4, "SELECT item2 FROM metaData WHERE id = 'password'")
    i = row[0][0].find(PBKDF2) if row and isinstance(row[0][0], bytes) else -1
    if i < 0: return None
    try:
        params, _ = der(row[0][0][i + len(PBKDF2):])
        _salt, rest = der(params)
        return int.from_bytes(der(rest)[0], 'big') == 1
    except IndexError: return None


# Site permissions worth a look: "click Allow to prove you are not a robot" pages use notifications to push fake virus alerts.
SITE_PERMS = {'notifications': 'send you notifications', 'media_stream_camera': 'use your camera', 'media_stream_mic': 'use your microphone',
              'geolocation': 'see your location'}
FF_PERMS = {'desktop-notification': 'notifications', 'camera': 'media_stream_camera', 'microphone': 'media_stream_mic', 'geo': 'geolocation'}


def site(pattern):
    """'https://[*.]example.com:443,*' (Chromium) or 'https://example.com^userContextId=1' (Firefox) -> 'example.com'"""
    return re.sub(r'^\w+://|:\d+$', '', re.split(r'[,^]', pattern)[0].replace('[*.]', ''))


def site_rows(name, grants):
    """grants: {permission: sites allowed}."""
    from .intel import domain_hit   # ponytail: intel imports this module, so it is imported late
    for perm, sites in grants.items():
        sites = sorted(set(sites))
        for h in sites:
            if hit := domain_hit(h):
                yield alert(f'{name}: {h} may {SITE_PERMS[perm]} and is on threat list {hit}',
                            fix='Block it in the browser (Settings > Privacy and security > Site settings), and ignore any virus warning it showed.')
        if sites: yield item(f'{name}: {len(sites)} site{"s" if len(sites) > 1 else ""} may {SITE_PERMS[perm]}: '
                             f'{", ".join(sites[:8])}{" and more" if len(sites) > 8 else ""}',
                             fix='Remove the ones you do not know: Settings > Privacy and security > Site settings (Firefox: Settings > Privacy & Security > Permissions).')


@check('Site permissions', 'Browsers')
def site_permissions():
    """Sites allowed to send notifications or use the camera, microphone or location, and any of them on a threat list."""
    for name, prof in chromium_profiles():
        ex = (jsonf(f'{prof}/Preferences').get('profile') or {}).get('content_settings', {}).get('exceptions', {})
        yield from site_rows(label(name, prof), {k: [site(o) for o, v in (ex.get(k) or {}).items() if isinstance(v, dict) and v.get('setting') == 1]
                                                 for k in SITE_PERMS})
    for prof in sorted({os.path.dirname(p) for r in FIREFOX for p in files(f'{r}/*/permissions.sqlite')}):
        grants = {}
        for origin, t in copy_query(f'{prof}/permissions.sqlite', 'SELECT origin, type FROM moz_perms WHERE permission = 1'):
            if t in FF_PERMS: grants.setdefault(FF_PERMS[t], []).append(site(origin))
        yield from site_rows(f'Firefox ({os.path.basename(prof).partition(".")[2] or os.path.basename(prof)})', grants)


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


HIJACK_FIX = ('If you did not choose it, set it back in Settings (Search engine, On startup, Appearance > Home button) and remove '
              'any extension or program you do not recognise: changing these is what browser hijackers and adware do.')


def page_rows(who, what, url, custom=True):
    """One row for a search engine or page a browser was set to: an alert when the link is dangerous, a list entry when it is not a built-in choice."""
    from .intel import link_signs   # ponytail: intel imports this module, so import late
    host = urllib.parse.urlsplit(url).hostname or url[:80]
    if bad := link_signs(url.replace('{searchTerms}', 'x'))[0]:
        yield alert(f'{who} {what} {host}: {bad[0]}', fix=HIJACK_FIX)
    elif what.endswith('go to') and url.startswith('http://'):
        yield warn(f'{who} {what} {host} without encryption', fix=HIJACK_FIX)
    elif custom: yield item(f'{who} {what} {host}', fix=HIJACK_FIX)


def hijack_rows(who, prefs):
    """The default search engine (only when it is not one of the browser's built-in choices), pages opened at start, and the home page."""
    d = (prefs.get('default_search_provider_data') or {}).get('mirrored_template_url_data') or {}
    s = prefs.get('session') or {}
    if isinstance(d.get('url'), str): yield from page_rows(f'{who}:', 'searches go to', d['url'], not d.get('prepopulate_id'))
    for u in s.get('startup_urls') or [] if s.get('restore_on_startup') == 4 else []:   # 4 = open specific pages
        if isinstance(u, str) and u: yield from page_rows(f'{who}:', 'start page is', u)
    if isinstance(prefs.get('homepage'), str) and prefs['homepage'] and prefs.get('homepage_is_newtabpage') is False:
        yield from page_rows(f'{who}:', 'home page is', prefs['homepage'])


def override_rows(exts):
    """Extensions whose manifest takes over the search engine, home page or start pages (chrome_settings_overrides)."""
    for browser, title, _, m in exts:
        o = m.get('chrome_settings_overrides') if isinstance(m, dict) else None
        if not isinstance(o, dict): continue
        who = f'{browser}: extension "{title}"'
        if isinstance(sp := o.get('search_provider'), dict) and isinstance(sp.get('search_url'), str):
            yield from page_rows(who, 'sends your searches to', sp['search_url'])
        if isinstance(o.get('homepage'), str): yield from page_rows(who, 'sets the home page to', o['homepage'])
        for u in o.get('startup_pages') or []:
            if isinstance(u, str): yield from page_rows(who, 'sets the start page to', u)


@check('Search and start page', 'Browsers')
def search_and_start():
    """What the address bar searches with and what opens at start: a changed one is the mark of a browser hijacker."""
    for name, prof in chromium_profiles(): yield from hijack_rows(label(name, prof), jsonf(f'{prof}/Preferences'))
    yield from override_rows(chromium_extensions())


def subject(pem):
    s = sh('openssl', 'x509', '-noout', '-subject', '-in', pem).strip()
    return (re.search(r'CN\s*=\s*([^,/]+)', s) or re.search(r'O\s*=\s*([^,/]+)', s) or [None, os.path.basename(pem)])[1].strip()


def nss_cas(db):
    """Nicknames of certificates an NSS database trusts as a CA for websites (trust flags with C in the SSL field)."""
    return [n.strip() for n, ssl in re.findall(r'^(.+?)\s{2,}([A-Za-z]*),[A-Za-z]*,[A-Za-z]*[ \t]*$', sh('certutil', '-L', '-d', f'sql:{db}', timeout=15), re.M) if 'C' in ssl]


# Discord and its web wrappers: the account token sits in Local Storage. Discord marks encrypted ones dQw4w9WgXcQ:,
# and djEw is base64 of v10, Chromium's built-in key. Unencrypted, it is "<base64 user id>.<time>.<hmac>".
DISCORD = {'~/.config/discord': 'Discord', '~/.config/discordcanary': 'Discord Canary', '~/.config/discordptb': 'Discord PTB',
           '~/.var/app/com.discordapp.Discord/config/discord': 'Discord (Flatpak)', '~/.config/vesktop': 'Vesktop',
           '~/.var/app/dev.vencord.Vesktop/config/vesktop': 'Vesktop (Flatpak)', '~/.config/legcord': 'Legcord', '~/.config/WebCord': 'WebCord'}

FILEZILLA = ('~/.config/filezilla', '~/.var/app/org.filezillaproject.Filezilla/config/filezilla')
REMMINA = ('~/.local/share/remmina/*.remmina', '~/.var/app/org.remmina.Remmina/data/remmina/*.remmina')   # key beside them in remmina.pref


def discord_token(b):
    """Whether Local Storage bytes hold a Discord token that needs no keyring to read (the value is never kept)."""
    if b'dQw4w9WgXcQ:djEw' in b: return True
    for m in re.finditer(rb'"([\w-]{23,27})\.[\w-]{6}\.[\w-]{27,38}"', b):   # ponytail: a token split by leveldb's compression is missed
        try:
            if base64.urlsafe_b64decode(m[1] + b'=' * (-len(m[1]) % 4)).isdigit(): return True
        except ValueError: pass
    return False


@check('Stealable app sign-ins', 'Privacy')
def sign_ins():
    """App sign-ins any program can copy and replay to be logged in as you, past the password and 2FA (what
    Discord-token stealers in cheats, cracked games and "free Nitro" tools take), and server passwords kept readable
    (FileZilla without a master password, Remmina without the keyring)."""
    for d, app in DISCORD.items():
        for f in files(f'{d}/Local Storage/leveldb/*.ldb', f'{d}/Local Storage/leveldb/*.log'):
            try:
                with open(f, 'rb') as fh: b = fh.read(64 << 20)
            except OSError: continue
            if discord_token(b):
                yield item(f'{app} keeps your sign-in token where any program can read it',
                           fix='A stealer that copies it is signed in as you without your password or 2FA; Discord on Linux does not '
                               'encrypt it. Keep cheats, cracked games and "free Nitro" tools off this PC; if one ran, change your Discord '
                               'password, which signs out every copied token.')
                break
    for f in files(*(f'{d}/{x}' for d in FILEZILLA for x in ('sitemanager.xml', 'recentservers.xml'))):
        if n := len(re.findall(r'<Pass(?: encoding="base64")?>[^<]', text(f))):   # with a master password: encoding="crypt"
            yield warn(f'FileZilla keeps {n} server password{"s" * (n > 1)} in plain text ({os.path.basename(f)})',
                       fix='Settings > Interface > Passwords: "Save passwords protected by a master password". Then change those '
                           'server passwords: stealers copy this file first.')
    n = sum(bool(re.search(r'^password=(?!\.?$).+', text(f), re.M)) for f in files(*REMMINA))   # "." = kept in the keyring
    if n: yield warn(f'Remmina keeps {n} connection password{"s" * (n > 1)} that any program can decrypt',
                     fix='Install the Remmina keyring plugin (remmina-plugins-secret; remmina-plugin-secret on Debian and Ubuntu), then re-save those connections so the passwords move into the keyring.')


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
