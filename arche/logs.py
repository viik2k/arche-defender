# Activity from the system journal over the last week: bursts of wrong passwords (lock screen, sudo, login,
# admin prompts), SSH brute force and any login that followed it, new login accounts, users given admin rights, and
# protections switched off through sudo or pkexec.
# Who is in wheel right now is persistence.py; this module reports what changed and when.
import json, re, time
from collections import defaultdict
from .core import check, alert, warn, item, sh
from . import intel

DAYS, BURST, WINDOW = 7, 5, 600
IDENTS = ('sudo', 'su', 'sshd', 'sshd-session', 'polkitd', 'pkexec', 'useradd', 'usermod', 'gpasswd', 'login',
          'sddm-helper', 'plasmalogin-helper', 'gdm-password]', 'unix_chkpwd', 'kscreenlocker_greet')
SERVICE = {'kde': 'screen unlock', 'kscreenlocker': 'screen unlock', 'polkit-1': 'admin password prompt',
           'plasmalogin': 'login screen', 'sddm': 'login screen', 'gdm-password': 'login screen', 'login': 'console login',
           'sudo': 'sudo prompt', 'su': 'su prompt', 'chkpwd': 'screen lock or app password prompt'}
ADMIN = {'wheel': 'can run anything as root with sudo', 'sudo': 'can run anything as root with sudo',
         'admin': 'can run anything as root with sudo', 'root': 'root group',
         'docker': 'root-equivalent: docker can mount / without a password', 'libvirt': 'root-equivalent through VMs',
         'lxd': 'root-equivalent through containers', 'disk': 'can read every disk directly', 'adm': 'can read all system logs',
         'input': 'every program it runs can read keystrokes', 'uinput': 'every program it runs can type as you'}

TAMPER = [(re.compile(p), what) for p, what in (
    (r'\bsetenforce\s+(0|[Pp]ermissive)\b', 'put SELinux in permissive mode'),
    (r'\bsystemctl\b.*\b(stop|disable|mask)\b.*\b(firewalld|ufw|nftables|apparmor|auditd|fapolicyd|clamd\S*|clamav\S*)\b', 'stopped a protection service'),
    (r'\bufw\s+disable\b|\bfirewall-cmd\b.*(--set-default-zone[= ]trusted|--set-target[= ]ACCEPT)', 'opened the firewall'),
    (r'\b(ip6?tables)\s+(-F|--flush)\b|\bnft\s+flush\s+ruleset\b', 'flushed the firewall rules'),
    (r'/etc/sudoers|\bvisudo\b', 'changed who may use sudo'),
    (r'\bpasswd\s+(-d|--delete)\b', 'removed an account password'),
    (r'\bmokutil\s+--disable-validation\b', 'turned off Secure Boot checks'),
    (r'\b(mitigations=off|selinux=0|enforcing=0|apparmor=0)\b', 'weakened the kernel command line'),
    (r'\bsysctl\b.*\b(ptrace_scope|kptr_restrict|randomize_va_space|dmesg_restrict|unprivileged_bpf_disabled)\s*=\s*0\b', 'weakened kernel hardening'),
    (r'\bchmod\s+(-R\s+)?0?777\s+/(etc|usr|bin|sbin|boot|lib)', 'made system files writable by everyone'),
    (r'\b(rm|truncate|shred)\b.*\s/var/log/|\bjournalctl\b.*--vacuum|\bchattr\s+[-+]i\b', 'deleted logs or changed immutable files'))]


def journal(days=DAYS):
    """(epoch seconds, identifier, message) for authentication and account events."""
    out = sh('journalctl', '-q', '--no-pager', '--since', f'-{days}d', '-o', 'json',
             *(f'SYSLOG_IDENTIFIER={i}' for i in IDENTS), timeout=60)
    for l in out.splitlines():
        try: e = json.loads(l)
        except ValueError: continue
        m = e.get('MESSAGE') or ''
        if isinstance(m, list): m = bytes(m).decode('utf-8', 'replace')   # journald sends non-UTF-8 text as bytes
        yield int(e.get('__REALTIME_TIMESTAMP', 0)) / 1e6, e.get('SYSLOG_IDENTIFIER', ''), m


def burst(times, window=WINDOW):
    """Most events inside any `window` seconds, and when that run started."""
    times, best, start, j = sorted(times), 0, None, 0
    for i, t in enumerate(times):
        while t - times[j] > window: j += 1
        if i - j + 1 > best: best, start = i - j + 1, times[j]
    return best, start


def when(t): return time.strftime('%a %d %b %H:%M', time.localtime(t))


def analyse(events):
    fails, ssh_bad, ssh_ok = defaultdict(list), defaultdict(int), {}
    for t, ident, m in events:
        if r := re.search(r'pam_unix\(([\w-]+):auth\): authentication failure', m):
            if r[1] != 'sshd': fails[r[1]].append(t)   # SSH is counted per address below
        elif ident == 'unix_chkpwd' and 'password check failed' in m: fails['chkpwd'].append(t)
        elif 'user NOT in sudoers' in m:
            yield alert(f'An account without admin rights tried sudo on {when(t)}: {m.strip()[:120]}',
                        fix='If that was not you, check what runs under that account (another user, or malware).')
        # "Failed password for invalid user" repeats the "Invalid user" line, so only one of the two is counted.
        elif ident in ('sudo', 'pkexec') and (c := re.search(r'COMMAND=([^\]\n]+)', m)):
            if what := next((w for rx, w in TAMPER if rx.search(c[1])), None):
                yield warn(f'{what[0].upper()}{what[1:]} with {ident} on {when(t)}: {c[1].strip()[:120]}',
                           fix='If you did not do this, undo it and look at what else ran then (Software installed this week, Startup entries).')
        elif r := re.search(r'Failed \S+ for (?!invalid user )\S+ from (\S+)|Invalid user \S* ?from (\S+)', m):
            ssh_bad[r[1] or r[2]] += 1
        elif r := re.search(r'Accepted (\S+) for (\S+) from (\S+)', m): ssh_ok.setdefault((r[2], r[3]), r[1])
        elif r := re.search(r'new user: name=([^,]+), UID=(\d+)', m):
            if 1000 <= int(r[2]) < 60000:
                yield warn(f'New login account {r[1]} was created on {when(t)}', fix=f'If you did not create it: sudo userdel -r {r[1]}')
            else: yield item(f'New system account {r[1]} (usually added by a package)')
        elif r := re.search(r"add '([^']+)' to group '([^']+)'|user (\S+) added by \S+ to group (\S+)", m):
            user, group = (r[1], r[2]) if r[1] else (r[3], r[4])
            if group in ADMIN:
                yield warn(f'{user} was added to the {group} group on {when(t)} ({ADMIN[group]})',
                           fix=f'If that was not you: sudo gpasswd -d {user} {group}')
    for svc, ts in fails.items():
        n, at = burst(ts)
        if n >= BURST:
            yield warn(f'{n} wrong passwords at the {SERVICE.get(svc, svc)} within {WINDOW // 60} minutes ({when(at)})',
                       fix='If that was not you, someone tried to guess your password. Lock the screen when away and use a long passphrase.')
    for ip, n in ssh_bad.items():
        if n >= BURST:
            hit = intel.ip_hit(ip)
            yield warn(f'{n} failed SSH logins from {ip}' + (f' (on threat list {hit})' if hit else ''),
                       fix='Allow keys only (PasswordAuthentication no), limit SSH to your LAN in firewalld, or stop sshd if unused.')
    for (user, ip), how in ssh_ok.items():
        if ssh_bad.get(ip, 0) >= BURST:
            yield alert(f'SSH login as {user} from {ip} succeeded after {ssh_bad[ip]} failures',
                        fix='Treat the account as compromised: change its password, check ~/.ssh/authorized_keys, block the address.')
        else: yield item(f'SSH login as {user} from {ip} ({how})')


@check('Login and account activity', 'Activity')
def activity():
    """Last week of the system journal: password guessing, SSH brute force, new accounts and new admins."""
    yield from analyse(journal())


ROUTINE = re.compile(r'\b(upgrade|update|distro-sync|makecache|check-upgrade|offline)\b')


@check('Software installed this week', 'Activity')
def installed():
    """dnf transactions and Flatpak apps installed or removed in the last week (routine upgrades left out)."""
    cut = time.time() - DAYS * 86400
    try: tx = json.loads(sh('dnf', '-C', '-q', 'history', 'list', '--json', timeout=60) or '[]')
    except ValueError: tx = []
    for t in tx:
        cmd = (t.get('command_line') or '').strip() or 'Discover or PackageKit'
        if t.get('start_time', 0) >= cut and not ROUTINE.search(cmd):
            yield item(f'dnf: {cmd[:120]} ({t.get("altered_count", "?")} packages, {when(t["start_time"])})')
    since = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cut))
    for l in sh('flatpak', 'history', f'--since={since}', '--columns=change,ref,remote,installation', timeout=30).splitlines():
        f = l.split('\t')
        if len(f) >= 4 and f[1].startswith('app/') and f[0] in ('deploy install', 'uninstall'):
            yield item(f'Flatpak {"installed" if f[0] != "uninstall" else "removed"} {f[1].split("/")[1]} from {f[2] or "?"} ({f[3]})')
