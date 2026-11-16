# Updates and vulnerabilities: OS support end, pending (security) package updates, reboot-needed kernels,
# Flatpak and firmware updates, fwupd's Host Security ID, and CPU vulnerability mitigations.
# How long since the last update is hardening.py's 'Security posture'; this module covers what is still waiting.
import json, os, re, time
from datetime import date
from .core import check, alert, warn, item, sh, have, text, files

UPGRADE = 'Update with the Nobara updater or: sudo dnf upgrade --refresh'


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
