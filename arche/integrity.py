# Integrity and rootkit checks: are the system's own tools still the ones the packages shipped, and is anything
# hiding from /proc, the module list or the network stack? Read-only; without root it sees your own processes' memory maps.
import os, re
from .core import PKG, REINSTALL, alert, warn, item, ver, sh, text, lines, files, check, owner
from .hardening import INFRA_IF

CRITICAL = {   # the tools attackers swap to hide (ls, ps, ss, sudo, sshd...), per package manager
    'rpm': ('coreutils', 'util-linux', 'procps-ng', 'findutils', 'grep', 'sed', 'gawk', 'bash', 'iproute', 'net-tools',
            'openssh', 'openssh-clients', 'openssh-server', 'sudo', 'shadow-utils', 'pam', 'polkit', 'systemd', 'glibc',
            'passwd', 'login', 'kmod', 'lsof', 'psmisc', 'cronie', 'curl', 'wget', 'tar', 'gzip', 'xz'),
    'dpkg': ('coreutils', 'util-linux', 'procps', 'findutils', 'grep', 'sed', 'gawk', 'mawk', 'bash', 'iproute2', 'net-tools',
             'openssh-client', 'openssh-server', 'sudo', 'passwd', 'login', 'kmod', 'lsof', 'psmisc', 'cron', 'curl', 'wget',
             'tar', 'gzip', 'xz-utils', 'libc-bin', 'libc6', 'systemd', 'libpam-modules', 'libpam-runtime', 'polkitd'),
    'pacman': ('coreutils', 'util-linux', 'procps-ng', 'findutils', 'grep', 'sed', 'gawk', 'bash', 'iproute2', 'net-tools',
               'openssh', 'sudo', 'shadow', 'pam', 'polkit', 'systemd', 'glibc', 'kmod', 'lsof', 'psmisc', 'cronie', 'curl',
               'wget', 'tar', 'gzip', 'xz')}.get(PKG, ())
PROG = re.compile(r'^/(usr/)?(s?bin|lib|lib64|libexec)/')   # program files; config and data change legitimately
DROP = re.compile(r'^(/tmp/|/var/tmp/|/dev/shm/|/run/user/\d+/|' + re.escape(os.path.expanduser('~/Downloads/')) + ')')
KTHREAD = re.compile(r'^(kworker|ksoftirqd|kthreadd|migration|rcu_|watchdog|irq/|kswapd|jbd2|kauditd|khungtaskd|oom_reaper|'
                     r'writeback|kcompactd|kblockd|cpuhp|ksmd|khugepaged|scsi_|nvme|kdevtmpfs|netns|kintegrityd|kthrotld)')


def rpm_verify(out):
    """rpm -V / dpkg --verify output -> (path, problem) for changed or missing program files; config, docs and unreadable files skipped."""
    for l in out.splitlines():
        m = re.match(r'^(missing|[.\w?]{9})\s+([cdglr]?)\s+(/\S+)', l)
        if not m or m[2] in ('c', 'd', 'g', 'l', 'r') or 'Permission denied' in l: continue
        flags, path = m[1], m[3]
        if not PROG.match(path): continue
        if flags == 'missing': yield path, 'missing'
        elif flags[2] == '5': yield path, 'contents changed'


def pacman_verify(out):
    """pacman -Qkk output (LC_ALL=C) -> (path, problem), like rpm_verify."""
    seen = set()
    for pkg, path, why in re.findall(r'^warning: (\S+): (/.+?) \(([^()]+)\)$', out, re.M):
        why = 'missing' if 'No such file' in why else 'contents changed' if 'checksum' in why or 'Size' in why else ''
        if why and PROG.match(path) and path not in seen:
            seen.add(path)
            yield path, why


def verify(pkgs=None):
    """(path, problem) for program files that differ from their package, in `pkgs` or in every package when None."""
    if pkgs is not None:   # dpkg and pacman stop at a name that is not installed
        if PKG == 'dpkg': pkgs = [l[3:] for l in sh('dpkg-query', '-W', '-f', '${db:Status-Abbrev}${binary:Package}\n', *pkgs).splitlines() if l.startswith('ii')]
        elif PKG == 'pacman': pkgs = sh('pacman', '-Qq', *pkgs).split()
        if not pkgs: return
    t = 120 if pkgs else 1800
    if PKG == 'rpm': yield from rpm_verify(sh('rpm', '-V' if pkgs else '-Va', '--nomtime', '--nouser', '--nogroup', '--nomode', '--nordev', '--nocaps', *pkgs or (), timeout=t))
    elif PKG == 'dpkg': yield from rpm_verify(sh('dpkg', '--verify', *pkgs or (), timeout=t))
    elif PKG == 'pacman': yield from pacman_verify(sh('env', 'LC_ALL=C', 'pacman', '-Qkk', *pkgs or (), err=True, timeout=t))


def report(found):
    for path, why in found:
        pkg = owner(path) or '?'
        if why == 'missing': yield warn(f'System file missing: {path} ({pkg})', REINSTALL.format(pkg))
        else: yield alert(f'System program differs from its package: {path} ({pkg}): possible trojan',
                          f'Compare with a clean copy; {REINSTALL.format(pkg)} restores it')


@check('Core system tools', 'Integrity')
def core_tools():
    if CRITICAL: yield from report(verify(CRITICAL))


@check('All packaged programs', 'Integrity', slow=True)
def all_packages():
    # ponytail: verifying every packaged file takes minutes; the quick scan covers the tools attackers swap most.
    yield from report(verify())


def proc_pids(): return {int(p) for p in os.listdir('/proc') if p.isdigit()}


def tgid(pid):
    m = re.search(r'^Tgid:\s+(\d+)', text(f'/proc/{pid}/status'), re.M)
    return int(m[1]) if m else None


@check('Hidden processes', 'Integrity')
def hidden():
    # A rootkit hides a process from the /proc listing but usually can't stop /proc/<pid> from answering.
    listed = proc_pids()
    top = max([int(text('/proc/loadavg').split()[-1] or 0), *listed]) + 1000
    found = [p for p in range(1, top) if p not in listed and os.path.exists(f'/proc/{p}')]   # threads also answer
    after = proc_pids()   # a process born mid-probe shows up here and is not hidden
    for t in sorted({g for g in map(tgid, found) if g and g not in after and os.path.exists(f'/proc/{g}')}):
        yield alert(f'Process {t} ({text(f"/proc/{t}/comm").strip() or "?"}) is hidden from the process list: rootkit behaviour',
                    'Boot a live USB and scan the disk; do not trust tools on this system')
    mods = {l.split()[0] for l in text('/proc/modules').splitlines()}
    for d in files('/sys/module/*/initstate'):
        m = d.split('/')[3]
        if m not in mods: yield alert(f'Kernel module {m} is in /sys but missing from /proc/modules: hidden module',
                                      'Boot a live USB and inspect; a hidden kernel module means the kernel is compromised')
    for m in sorted(set(re.findall(r'\t\[(\w+)\]$', text('/proc/kallsyms'), re.M)) - mods - {'bpf'}):
        yield alert(f'Kernel symbols from module {m}, which is not in the module list: hidden module', 'Boot a live USB and inspect')


@check('Process tampering', 'Integrity')
def tamper():
    for pid in sorted(proc_pids()):
        st = text(f'/proc/{pid}/stat')
        comm = text(f'/proc/{pid}/comm').strip()
        f = st.rpartition(')')[2].split()
        if len(f) < 7: continue
        kthread = int(f[6]) & 0x00200000   # PF_KTHREAD
        cmd = text(f'/proc/{pid}/cmdline').replace('\0', ' ').strip()
        if not kthread and (KTHREAD.match(comm) or cmd.startswith('[')):
            yield alert(f'Process {pid} pretends to be a kernel thread: {cmd or comm}', f'Inspect /proc/{pid}/exe, then kill {pid}')
        try: exe = os.readlink(f'/proc/{pid}/exe')
        except OSError: exe = ''
        for l in text(f'/proc/{pid}/maps').splitlines():   # own processes only without root
            p = l.split(None, 5)
            if len(p) < 6 or 'x' not in p[1]: continue
            lib = p[5]
            if '.so' in lib and DROP.match(lib): yield alert(f'{comm} ({pid}) runs code from a temp/download folder: {lib}', f'Inspect {lib}')
            elif lib.endswith('(deleted)') and '.so' in lib and not lib.startswith('/memfd:'):
                yield item(ver(f'{comm} uses a library replaced on disk (restart it): {lib.removesuffix(" (deleted)")}'))
        env = text(f'/proc/{pid}/environ')
        for pre in re.findall(r'(?:^|\0)LD_PRELOAD=([^\0]+)', env):
            for lib in re.split(r'[: ]', pre):
                if not lib: continue
                if DROP.match(lib): yield alert(f'{comm} ({pid}) is injected with a library from a temp folder: {lib}')
                else: yield item(ver(f'LD_PRELOAD in {comm}: {lib}'))
        if exe and comm and not exe.endswith(' (deleted)') and comm[:15] in ('sshd', 'systemd', 'init', 'bash', 'sudo') \
                and not exe.startswith(('/usr/', '/bin/', '/sbin/')):
            yield alert(f'Process {pid} is named {comm} but runs {exe}', f'Inspect {exe}')


@check('Network sniffing and kernel state', 'Integrity')
def kstate():
    for f in files('/sys/class/net/*/flags'):
        dev = f.split('/')[4]
        if int(text(f).strip() or '0', 16) & 0x100 and not INFRA_IF.match(dev):
            yield warn(f'Network card {dev} is in promiscuous mode: something may be capturing traffic',
                       'Check with: ip -d link show ' + dev + ' (packet capture tools like Wireshark do this)')
    t = int(text('/proc/sys/kernel/tainted').strip() or 0)
    if t & 2: yield warn('A kernel module was force-loaded (taint F)', 'Check lsmod and dmesg for the module')
    if t & 8: yield warn('A kernel module was force-unloaded (taint R)', 'Check dmesg')
    if t & 128: yield item('The kernel has oopsed since boot (taint D); check dmesg')
    if t & 32768: yield item('Kernel is live-patched (taint K)')
