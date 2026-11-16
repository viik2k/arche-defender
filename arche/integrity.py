# Integrity and rootkit checks: are the system's own tools still the ones the packages shipped, and is anything
# hiding from /proc, the module list or the network stack? Read-only; without root it sees your own processes' memory maps.
import os, re
from .core import alert, warn, item, ver, sh, text, lines, files, check
from .hardening import INFRA_IF

CRITICAL = ('coreutils', 'util-linux', 'procps-ng', 'findutils', 'grep', 'sed', 'gawk', 'bash', 'iproute', 'net-tools',
            'openssh', 'openssh-clients', 'openssh-server', 'sudo', 'shadow-utils', 'pam', 'polkit', 'systemd', 'glibc',
            'passwd', 'login', 'kmod', 'lsof', 'psmisc', 'cronie', 'curl', 'wget', 'tar', 'gzip', 'xz')
DROP = re.compile(r'^(/tmp/|/var/tmp/|/dev/shm/|/run/user/\d+/|' + re.escape(os.path.expanduser('~/Downloads/')) + ')')
KTHREAD = re.compile(r'^(kworker|ksoftirqd|kthreadd|migration|rcu_|watchdog|irq/|kswapd|jbd2|kauditd|khungtaskd|oom_reaper|'
                     r'writeback|kcompactd|kblockd|cpuhp|ksmd|khugepaged|scsi_|nvme|kdevtmpfs|netns|kintegrityd|kthrotld)')


def rpm_verify(out):
    """rpm -V output -> (path, problem) for changed or missing program files; config, docs and unreadable files skipped."""
    for l in out.splitlines():
        m = re.match(r'^(missing|[.\w?]{9})\s+([cdglr]?)\s+(/\S+)', l)
        if not m or m[2] in ('c', 'd', 'g', 'l', 'r') or 'Permission denied' in l: continue
        flags, path = m[1], m[3]
        if not re.match(r'^/(usr/)?(s?bin|lib|lib64|libexec)/', path): continue
        if flags == 'missing': yield path, 'missing'
        elif flags[2] == '5': yield path, 'contents changed'


def report_verify(out):
    for path, why in rpm_verify(out):
        owner = sh('rpm', '-qf', '--qf', '%{NAME}', path).strip()
        if why == 'missing': yield warn(f'System file missing: {path} ({owner})', f'sudo dnf reinstall {owner}')
        else: yield alert(f'System program differs from its package: {path} ({owner}): possible trojan',
                          f'Compare with a clean copy; sudo dnf reinstall {owner} restores it')


@check('Core system tools', 'Integrity')
def core_tools():
    yield from report_verify(sh('rpm', '-V', *CRITICAL, timeout=120))


@check('All packaged programs', 'Integrity', slow=True)
def all_packages():
    # ponytail: rpm -Va reads every packaged file (a few minutes); the quick scan covers the tools attackers swap most.
    yield from report_verify(sh('rpm', '-Va', '--nomtime', '--nouser', '--nogroup', '--nomode', '--nordev', '--nocaps', timeout=1800))


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
