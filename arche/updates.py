# Updates and vulnerabilities: OS support end, pending (security) package updates, reboot-needed kernels,
# Flatpak and firmware updates, fwupd's Host Security ID, and CPU vulnerability mitigations;
# apps that bundle a browser engine (Electron) too old to still get security fixes.
# How long since the last update is hardening.py's 'Security posture'; this module covers what is still waiting.
import configparser, json, mmap, os, re, time
from datetime import date
from .core import check, alert, warn, item, sh, have, text, files, jsonf, HOME, UPGRADE as UPGRADE_CMD
from .intel import ELECTRON

UPGRADE = f'Update with your desktop\'s updater or: {UPGRADE_CMD}'


def os_release(): return dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', text('/etc/os-release'), re.M))


@check('Operating system support', 'Updates')
def support():
    r = os_release()
    try: end = date.fromisoformat(r.get('SUPPORT_END', ''))
    except ValueError: return
    days, name = (end - date.today()).days, r.get('PRETTY_NAME') or r.get('NAME', 'This OS')
    if days < 0: yield alert(f'{name} stopped getting security updates on {end}', fix='Upgrade to the current release.')
    elif days <= 45: yield warn(f'{name} stops getting security updates on {end} (in {days} days)', fix='Plan the upgrade to the next release.')


def natural(s): return [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', s)]


def newest_same_flavor(running, installed):
    """Newest installed kernel of the running kernel's flavour (so an -eac or -rt kernel beside it does not count)."""
    flavor = lambda k: re.sub(r'\d+', '#', k)
    same = [k for k in installed if flavor(k) == flavor(running)]
    return max(same, key=natural) if same else running


@check('Pending updates', 'Updates')
def pending():
    """Package updates waiting (from the package manager's cached metadata; no download) and a newer kernel than the running one."""
    if have('dnf'):
        ups = [l for l in sh('dnf', '-C', '-q', 'check-upgrade', timeout=120).splitlines() if re.match(r'^\S+\.\w+\s+\S+\s+\S+', l)]
        sec = [l for l in sh('dnf', '-C', '-q', 'advisory', 'list', '--security', timeout=120).splitlines() if re.match(r'^\S+-\d', l)]
    elif have('apt'):
        ups = [l for l in sh('apt', 'list', '--upgradable', timeout=120).splitlines() if '/' in l]
        sec = [l for l in ups if '-security' in l]
    elif have('checkupdates'):
        ups, sec = sh('checkupdates', timeout=120).splitlines(), []   # Arch has no security metadata
    else: ups, sec = [], []
    if sec:
        crit = sum('Critical' in l for l in sec)
        yield (alert if crit else warn)(f'{len(sec)} security updates waiting' + (f', {crit} critical' if crit else ''), fix=UPGRADE)
    if ups: yield warn(f'{len(ups)} package updates waiting', fix=UPGRADE)
    run = os.uname().release
    kernels = [os.path.basename(os.path.dirname(p)) for p in files('/lib/modules/*/vmlinuz')] or \
              [os.path.basename(p)[8:] for p in files('/boot/vmlinuz-*')]
    new = newest_same_flavor(run, kernels)
    if natural(new) > natural(run): yield warn(f'Reboot needed: running kernel {run}, newer {new} is installed',
                                               fix='Restart to load the patched kernel.')


@check('Flatpak updates', 'Updates', slow=True)
def flatpaks():
    """Asks the Flatpak remotes, so it needs the network and runs only in a full scan."""
    if not have('flatpak'): return
    ups = [l for l in sh('flatpak', 'remote-ls', '--updates', '--columns=application', timeout=180).splitlines() if '.' in l]
    if ups: yield warn(f'{len(ups)} Flatpak updates waiting: {", ".join(ups[:5])}{"..." if len(ups) > 5 else ""}', fix='Run: flatpak update')
    eol = re.findall(r'^(\S+)\s.*end-of-life', sh('flatpak', 'list', '--columns=application,options', timeout=60), re.M | re.I)
    for a in eol: yield warn(f'Flatpak {a} uses an end-of-life runtime', fix='Run: flatpak update; if it stays, the app is unmaintained.')


def hsi(attrs):
    """fwupd's Host Security ID level: the highest level whose attributes all pass; '!' when runtime issues exist."""
    level = 0
    for lvl in range(1, 6):
        at = [a for a in attrs if a.get('HsiLevel') == lvl]
        if not at or any('success' not in (a.get('Flags') or []) for a in at): break
        level = lvl
    bang = any(not a.get('HsiLevel') and 'success' not in (a.get('Flags') or []) for a in attrs)
    return f'HSI:{level}{"!" if bang else ""}'


@check('Firmware', 'Updates')
def firmware():
    """Firmware updates from fwupd's cached metadata, and the platform security attributes fwupd checks (HSI)."""
    if not have('fwupdmgr'): return
    try: devs = json.loads(sh('fwupdmgr', 'get-updates', '--json', '--no-unreported-check', timeout=60) or '{}').get('Devices', [])
    except ValueError: devs = []
    for d in devs:
        rel = (d.get('Releases') or [{}])[0]
        yield warn(f'Firmware update for {d.get("Name")}: {d.get("Version")} -> {rel.get("Version")}', fix='Run: fwupdmgr update (or use Discover).')
    try: attrs = json.loads(sh('fwupdmgr', 'security', '--json', '--no-unreported-check', timeout=60) or '{}').get('SecurityAttributes', [])
    except ValueError: return
    if not attrs: return
    yield item(f'Host Security ID: {hsi(attrs)}', fix='See: fwupdmgr security. Higher is better; ! means a runtime issue.')
    for a in attrs:
        if 'success' in (a.get('Flags') or []) or a.get('HsiResult') in ('not-supported',): continue
        # ponytail: fwupd failures are inventory, so a drop shows as new without nagging about firmware you cannot change.
        yield item(f'Platform protection not met: {a.get("Name")} ({a.get("HsiResult")})', fix=a.get('Description'))


@check('CPU vulnerabilities', 'Updates')
def cpu():
    for p in files('/sys/devices/system/cpu/vulnerabilities/*'):
        s = text(p).strip()
        if s.startswith('Vulnerable'): yield warn(f'CPU {os.path.basename(p)}: {s}', fix='Install the latest microcode (linux-firmware) and BIOS, and keep mitigations on.')
    cmd = text('/proc/cmdline')
    if re.search(r'\bmitigations=off\b', cmd): yield alert('The kernel was booted with mitigations=off', fix='Remove mitigations=off from the kernel command line (grubby --update-kernel=ALL --remove-args=mitigations=off).')
    for m in re.findall(r'\b(nospectre_v[12]|nopti|nospec_store_bypass_disable|tsx=on|nosmap|nosmep|noibrs|noibpb)\b', cmd):
        yield warn(f'Kernel command line weakens a CPU mitigation: {m}', fix='Remove it from the kernel command line unless you need it.')


def dnf_repo_rows(repos):
    """Enabled dnf repos (from `dnf repo info --json`, which has the effective signature setting)."""
    for r in repos:
        if not r.get('is_enabled', True): continue
        urls = [u for u in (*(r.get('base_url') or []), r.get('metalink'), r.get('mirrorlist')) if u]
        name, host = r.get('id', '?'), re.sub(r'^\w+://([^/]+).*$', r'\1', urls[0]) if urls else 'no URL'
        if not r.get('pkg_gpgcheck'):
            yield warn(f'Packages from repo {name} ({host}) are installed without a signature check',
                       fix=f'Set gpgcheck=1 in {r.get("repo_file_path") or "its .repo file"} and import the vendor key, or remove the repo.')
        elif any(u.startswith('http://') for u in urls): yield item(f'Repo {name} is fetched over plain http ({host}); its packages are still signature-checked')
        else: yield item(f'Package source: {name} ({host})')


@check('Package sources', 'Updates')
def sources():
    """Where software comes from: every enabled repo and Flatpak remote, and any that skip signature or TLS checks."""
    if have('dnf'):
        try: yield from dnf_repo_rows(json.loads(sh('dnf', '-C', '-q', 'repo', 'info', '--enabled', '--json', timeout=60) or '[]'))
        except ValueError: pass
    for f in files('/etc/yum.repos.d/*.repo', '/etc/dnf/dnf.conf'):
        if re.search(r'^\s*sslverify\s*=\s*(0|false|no)\b', text(f), re.M | re.I):
            yield warn(f'{f} turns off TLS certificate checks (sslverify=0)', fix=f'Remove sslverify=0 from {f}.')
    for f in files('/etc/apt/sources.list', '/etc/apt/sources.list.d/*'):
        if re.search(r'trusted\s*[=:]\s*yes|allow-insecure\s*[=:]\s*yes', text(f), re.I):
            yield warn(f'{f} trusts a source without signatures (trusted=yes)', fix='Remove trusted=yes and add the vendor key with signed-by=.')
    c = configparser.ConfigParser(interpolation=None, strict=False)
    for where, f in (('system', '/var/lib/flatpak/repo/config'), ('user', f'{HOME}/.local/share/flatpak/repo/config')):
        c.clear()
        try: c.read_string(text(f))
        except configparser.Error: continue
        for sec in c.sections():
            if not (m := re.match(r'remote "(.+)"$', sec)): continue
            if c[sec].get('gpg-verify', 'true').lower() == 'false':
                yield warn(f'Flatpak remote {m[1]} ({where}) installs apps without a signature check',
                           fix=f'Run: flatpak remote-modify {"--user " if where == "user" else ""}--gpg-verify {m[1]}  (or remove the remote)')
            else: yield item(f'Flatpak remote {m[1]} ({where}): {c[sec].get("url", "?")}')


# Folders a Chromium runtime (marked by icudtl.dat) may sit in: packages, /opt, user installs, running AppImages, Flatpaks.
RUNTIMES = ('/usr/lib/*', '/usr/lib64/*', '/usr/share/*', '/opt/*', '/opt/*/*', '~/.local/share/*', '~/Applications/*', '/tmp/.mount_*',
            *(f'{r}/*/current/active/files{s}' for r in ('/var/lib/flatpak/app', '~/.local/share/flatpak/app') for s in ('', '/*')))
UA = re.compile(rb'Chrome/(\d+)\.\d+\.\d+\.\d+ Electron/(\d+\.\d+\.\d+)')


def electron_apps():
    """(name, folder, Electron version, Chromium major) for each Electron app: its main program carries the user-agent string."""
    for d in sorted({os.path.dirname(f) for f in files(*(f'{r}/icudtl.dat' for r in RUNTIMES))}):
        try: exes = [e.path for e in os.scandir(d) if e.is_file(follow_symlinks=False) and e.stat().st_size > (20 << 20) and os.access(e.path, os.X_OK)]
        except OSError: continue
        for exe in exes:
            try:
                with open(exe, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m: ua = (u := UA.search(m)) and u.groups()
            except (OSError, ValueError): continue
            if ua:
                fp = re.search(r'/flatpak/app/([^/]+)/', d)
                yield (fp[1] if fp else os.path.basename(exe)), d, ua[1].decode(), int(ua[0]); break


def supported_majors(releases):
    """The Electron majors still patched: the newest three with a stable release."""
    return set(sorted({int(r['version'].split('.')[0]) for r in releases if re.fullmatch(r'\d+\.\d+\.\d+', str(r.get('version', '')))})[-3:])


def electron_rows(apps, releases):
    ok = supported_majors(releases) if isinstance(releases, list) else set()
    for name, d, ver, chrome in apps:
        if ok and int(ver.split('.')[0]) not in ok:
            yield warn(f'{name} runs on Electron {ver} (Chromium {chrome}), which no longer gets security fixes',
                       fix=f'Update it (installed in {d.replace(HOME, "~")}). If it is already current, its makers ship an unsupported browser engine: '
                           'avoid opening untrusted links, files or messages in it.')
        else: yield item(f'{name} bundles Electron {ver.split(".")[0]} (Chromium {chrome})',   # ponytail: no patch level in the text, or every app update is "new"
                         fix=f'Electron {ver} in {d.replace(HOME, "~")}.' + ('' if ok else ' Run intel-update to learn whether it still gets security fixes.'))


@check('Built-in browser engines', 'Updates')
def electron():
    """Apps that bundle their own Chromium (Electron: VS Code, Discord, Obsidian...) are only as patched as the Electron they ship."""
    yield from electron_rows(electron_apps(), jsonf(ELECTRON))
