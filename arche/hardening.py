# Protection status: is the machine's own armour on? Firewall, SELinux, Secure Boot, disk encryption, kernel
# hardening, login and screen lock, SSH server, and files that hold secrets. Weak settings are WARN with a fix.
import os, re, stat, time
from .core import HOME, PKG, UPGRADE, alert, warn, item, sh, have, text, lines, files, check

INFRA_IF = re.compile(r'^(lo|docker\d*|br-|virbr|veth|tailscale|podman|cni|vnet|wg|zt)')


def plain_swap(swaps, kind=lambda d: sh('lsblk', '-n', '-s', '-o', 'TYPE', d).split()):
    """Swap partitions in /proc/swaps with no LUKS layer under them (zram is RAM, and a swap file shares its filesystem's encryption)."""
    return [d for d in re.findall(r'^(/dev/\S+)\s+partition', swaps, re.M) if not d.startswith('/dev/zram') and 'crypt' not in kind(d)]


@check('Security posture', 'Protection')
def security():
    active = lambda u: sh('systemctl', 'is-active', u).strip() == 'active'
    if not (active('firewalld') or re.search(r'^ENABLED=yes', text('/etc/ufw/ufw.conf'), re.M) or active('nftables')):
        yield alert('No firewall is on (firewalld, ufw or nftables)',
                    'sudo systemctl enable --now firewalld' if have('firewall-cmd') else 'sudo ufw enable' if have('ufw') else
                    {'dpkg': 'sudo apt install ufw && sudo ufw enable', 'pacman': 'sudo pacman -S ufw && sudo systemctl enable --now ufw && sudo ufw enable'}
                    .get(PKG, 'Install and enable firewalld or ufw'))
    db = next((p for p in ('/usr/lib/sysimage/rpm/rpmdb.sqlite', '/var/lib/rpm/rpmdb.sqlite', '/var/lib/rpm/Packages')
               if os.path.exists(p)), None) if PKG == 'rpm' else {'dpkg': '/var/lib/dpkg/status', 'pacman': '/var/lib/pacman/local'}.get(PKG)
    if db:
        age = int((time.time() - os.path.getmtime(db)) / 86400)
        if age > 14: yield alert(f'No package updates in {age} days', f'Install updates (your Software/Update app, or {UPGRADE})')
    se = sh('getenforce').strip()
    if se == 'Enforcing': yield item('SELinux: Enforcing')
    elif text('/sys/module/apparmor/parameters/enabled').strip() == 'Y' and se != 'Permissive': yield item('AppArmor: enabled')
    elif se or os.path.exists('/etc/selinux/config'):
        yield warn(f'SELinux is {se or "off"}: a compromised app is not confined',
                   'Set SELINUX=enforcing in /etc/selinux/config, then sudo touch /.autorelabel and reboot')
    else: yield warn('No SELinux or AppArmor: a compromised app is not confined',
                     {'dpkg': 'sudo apt install apparmor apparmor-utils, then reboot'}.get(PKG, 'Install AppArmor and add apparmor to the lsm= kernel parameter'))
    sb = sh('mokutil', '--sb-state').strip()
    if 'enabled' in sb: yield item(sb)
    elif sb: yield warn('Secure Boot is disabled: a bootkit or unsigned kernel module can load before the OS',
                        'Enable Secure Boot in firmware setup (enrol the NVIDIA/akmods key with mokutil first)')
    lock = re.search(r'\[(\w+)\]', text('/sys/kernel/security/lockdown'))
    if lock: yield item(f'Kernel lockdown: {lock[1]}')
    plain = []
    for mnt in ('/', '/home'):
        src = sh('findmnt', '-n', '-o', 'SOURCE', mnt).strip()
        if src and 'crypt' not in sh('lsblk', '-n', '-s', '-o', 'TYPE', src).split(): plain.append(mnt)
        elif src: yield item(f'{mnt} is encrypted (LUKS)')
    if plain: yield warn(f'Disk not encrypted ({", ".join(plain)}): anyone who takes the drive can read your files',
                         'Full-disk encryption (LUKS) is chosen at install time; back up and reinstall with encryption on')
    elif swap := plain_swap(text('/proc/swaps')):   # LUKS on / with a plain swap partition beside it: memory lands on disk in the clear
        yield warn(f'Swap is not encrypted ({", ".join(swap)}): passwords, keys and open files that were in memory are written there in the '
                   'clear, and so is a hibernation image', 'Switch to zram (swapoff that partition and remove it from /etc/fstab), or put swap inside LUKS')


@check('Firewall rules', 'Protection')
def firewall():
    if not have('firewall-cmd'): return
    from .exposure import public_v6   # firewalld zones cover IPv6 too, and an internet IPv6 address has no NAT in front of it
    v6 = ', and from the internet over IPv6 unless your router blocks it' if public_v6(sh('ip', '-6', '-o', 'addr', 'show', 'scope', 'global')) else ''
    zones = re.findall(r'^(\S+)[^\n]*\n\s+interfaces: (.*)$', sh('firewall-cmd', '--get-active-zones'), re.M)
    for zone, ifs in zones:
        ifs = [i for i in ifs.split() if not INFRA_IF.match(i)]
        if not ifs: continue
        conf = dict(re.findall(r'^\s+([\w-]+): ?(.*)$', sh('firewall-cmd', f'--zone={zone}', '--list-all'), re.M))
        if conf.get('target') == 'ACCEPT': yield warn(f'Zone {zone} ({", ".join(ifs)}) accepts all inbound traffic',
                                                      f'sudo firewall-cmd --permanent --zone={zone} --set-target=default && sudo firewall-cmd --reload')
        for s in conf.get('services', '').split(): yield item(f'Zone {zone} allows service: {s}')
        for p in conf.get('ports', '').split():
            m = re.match(r'(\d+)-(\d+)/', p)
            if m and int(m[2]) - int(m[1]) > 1000:
                yield warn(f'Zone {zone} opens ports {p} to your network{v6}: any app that listens is reachable',
                           f'sudo firewall-cmd --permanent --zone={zone} --remove-port={p} && sudo firewall-cmd --reload '
                           '(then add back only the ports you use)')
            else: yield item(f'Zone {zone} allows port: {p}')


# key, is-weak(value), why, recommended
SYSCTL = (('kernel.randomize_va_space', lambda v: v != '2', 'ASLR is weakened', '2'),
          ('kernel.kptr_restrict', lambda v: v == '0', 'kernel addresses are visible to every user (helps exploits)', '1'),
          ('kernel.dmesg_restrict', lambda v: v == '0', 'any user can read the kernel log', '1'),
          ('kernel.yama.ptrace_scope', lambda v: v == '0', 'any of your programs can read the memory of the others (browser, password manager); some Wine/mod tools want 0', '1'),
          ('kernel.unprivileged_bpf_disabled', lambda v: v == '0', 'unprivileged BPF is allowed (a common kernel exploit path)', '2'),
          ('fs.protected_symlinks', lambda v: v == '0', 'symlink attacks in /tmp are possible', '1'),
          ('fs.protected_hardlinks', lambda v: v == '0', 'hardlink attacks are possible', '1'),
          ('fs.protected_fifos', lambda v: v == '0', 'FIFO attacks in sticky dirs are possible', '1'),
          ('fs.protected_regular', lambda v: v == '0', 'file-squatting in sticky dirs is possible', '1'),
          ('fs.suid_dumpable', lambda v: v == '1', 'setuid programs dump core readable by you', '0'),
          ('net.ipv4.tcp_syncookies', lambda v: v == '0', 'no SYN-flood protection', '1'),
          ('net.ipv4.conf.all.accept_redirects', lambda v: v != '0', 'ICMP redirects can reroute your traffic', '0'),
          ('net.ipv6.conf.all.accept_redirects', lambda v: v != '0', 'ICMPv6 redirects can reroute your traffic', '0'),
          ('net.ipv4.conf.all.send_redirects', lambda v: v != '0', 'this PC sends ICMP redirects like a router', '0'),
          ('net.ipv4.conf.all.accept_source_route', lambda v: v != '0', 'source-routed packets are accepted', '0'))


@check('Kernel hardening', 'Protection')
def kernel():
    for key, weak, why, good in SYSCTL:
        v = text('/proc/sys/' + key.replace('.', '/')).strip()
        if not v: continue
        if weak(v): yield warn(f'{key} = {v}: {why}', f'echo "{key} = {good}" | sudo tee -a /etc/sysctl.d/90-arche.conf && sudo sysctl --system')
        else: yield item(f'{key} = {v}')
    if text('/proc/sys/net/ipv4/ip_forward').strip() == '1': yield item('IP forwarding is on (normal with Docker, libvirt or Tailscale exit nodes)')


@check('Login and screen lock', 'Protection')
def login():
    for f in files('/etc/sddm.conf', '/etc/sddm.conf.d/*.conf', '/etc/plasmalogin.conf', '/etc/plasmalogin.conf.d/*.conf'):
        m = re.search(r'^\[Autologin\][^\[]*?^User=(\S+)', text(f), re.M | re.S)
        if m: yield warn(f'Automatic login as {m[1]} ({f}): anyone at the keyboard gets your session', f'Remove User= under [Autologin] in {f}')
    if re.search(r'^AutomaticLoginEnable\s*=\s*true', text('/etc/gdm/custom.conf'), re.M | re.I):
        yield warn('GDM automatic login is on', 'Set AutomaticLoginEnable=False in /etc/gdm/custom.conf')
    kde = text(f'{HOME}/.config/kscreenlockerrc')
    if os.environ.get('XDG_CURRENT_DESKTOP', '').upper().find('KDE') >= 0 or kde:
        if re.search(r'^Autolock=false', kde, re.M): yield warn('Screen never locks when idle', 'System Settings > Screen Locking > Lock screen automatically')
        m = re.search(r'^Timeout=(\d+)', kde, re.M)
        if m and int(m[1]) > 15: yield warn(f'Screen locks only after {m[1]} minutes idle', 'System Settings > Screen Locking: 15 minutes or less')
        if re.search(r'^LockOnResume=false', kde, re.M): yield warn('Screen does not lock after sleep', 'System Settings > Screen Locking > Lock after waking from sleep')
    if have('gsettings') and 'GNOME' in os.environ.get('XDG_CURRENT_DESKTOP', '').upper():
        if sh('gsettings', 'get', 'org.gnome.desktop.screensaver', 'lock-enabled').strip() == 'false':
            yield warn('GNOME screen lock is off', 'Settings > Privacy > Screen Lock')
    if 'NOPASSWD' in sh('sudo', '-n', '-l', timeout=5):
        yield warn('sudo works without a password for this account: any program you run can become root',
                   'Remove NOPASSWD from /etc/sudoers.d (sudo visudo -f <file>)')


@check('SSH server', 'Protection')
def sshd():
    active = 'active' in sh('systemctl', 'is-active', 'sshd', 'ssh').split()   # 'ssh' on Debian/Ubuntu
    conf = '\n'.join(text(f) for f in ['/etc/ssh/sshd_config', *files('/etc/ssh/sshd_config.d/*.conf')])
    if not active: return
    yield item('sshd is running')
    if not conf.strip():
        yield item('sshd config needs root to read; run a scan with sudo to audit it'); return
    opt = {}
    for k, v in re.findall(r'^\s*(\w+)\s+(\S+)', conf, re.M): opt.setdefault(k.lower(), v.lower())   # first match wins in sshd
    if opt.get('permitrootlogin') == 'yes': yield warn('sshd allows root to log in with a password', 'PermitRootLogin prohibit-password (or no)')
    if opt.get('passwordauthentication', 'yes') == 'yes': yield warn('sshd accepts passwords (brute-forceable)', 'PasswordAuthentication no, after your key works')
    if opt.get('permitemptypasswords') == 'yes': yield alert('sshd accepts empty passwords', 'PermitEmptyPasswords no')



MITM = 'SSH connects to a server it has never seen, or whose key changed, without asking: a machine in the middle reads the session'
SSH_RISK = {('forwardagent', 'yes'): ('every server you log in to can use your SSH keys while you are connected: a hacked one logs in '
                                      'everywhere else as you', 'ForwardAgent yes only under the Host blocks you trust, or use ProxyJump'),
            ('forwardx11', 'yes'): ('every server you log in to can see and type into your desktop (X11 forwarding)',
                                    'ForwardX11 no; use ssh -X for the one session that needs it'),
            ('stricthostkeychecking', 'no'): (MITM, 'Remove it, or use accept-new (asks nothing for new servers, refuses changed keys)'),
            ('stricthostkeychecking', 'off'): (MITM, 'Remove it, or use accept-new (asks nothing for new servers, refuses changed keys)'),
            ('userknownhostsfile', '/dev/null'): (MITM, 'Remove UserKnownHostsFile /dev/null')}


def ssh_client_rows(t, where):
    """SSH client settings that apply to every host (top of the file, Host *, Match all): a per-host one is a choice for that host."""
    every = True
    for line in t.splitlines():
        if not (m := re.match(r'\s*(\w+)(?:\s*=\s*|\s+)(.+?)\s*$', line)) or line.lstrip().startswith('#'): continue
        k, v = m[1].lower(), m[2].strip('"').lower()
        if k in ('host', 'match'): every = v.split() in (['*'], ['all'], ['final', 'all'])
        elif every and (k, v) in SSH_RISK: yield warn(f'{where}: {m[1]} {m[2]} for every host: {SSH_RISK[k, v][0]}', SSH_RISK[k, v][1])


@check('SSH client', 'Protection')
def ssh_client():
    """SSH client settings that hand servers your keys or desktop, or skip the check that catches a fake server."""
    for f in files('/etc/ssh/ssh_config', '/etc/ssh/ssh_config.d/*.conf', '~/.ssh/config', '~/.ssh/config.d/*'):
        yield from ssh_client_rows(text(f), f.replace(HOME, '~'))


SECRET_FILES = ('~/.netrc', '~/.git-credentials', '~/.aws/credentials', '~/.config/gh/hosts.yml', '~/.docker/config.json',
                '~/.kube/config', '~/.pgpass', '~/.npmrc', '~/.pypirc', '~/.config/rclone/rclone.conf', '~/.ssh/config',
                '~/.claude.json', '~/.claude/.credentials.json', '~/.codex/auth.json', '~/.config/gcloud/credentials.db',
                # AI sign-ins: each is a live token for the account, and any process running as you can lift it
                '~/.gemini/oauth_creds.json', '~/.gemini/mcp-oauth-tokens.json', '~/.config/github-copilot/apps.json',
                '~/.config/github-copilot/hosts.json', '~/.mcp-auth/*/*_tokens.json', '~/.local/share/opencode/auth.json',
                '~/.cache/huggingface/token', '~/.huggingface/token', '~/.ollama/id_ed25519', '~/.openclaw/agents/*/agent/auth-profiles.json',
                # infostealers grab these too: FTP logins, the stream key (whoever has it streams as you), Terraform and Vault tokens
                '~/.config/filezilla/sitemanager.xml', '~/.config/filezilla/recentservers.xml', '~/.config/obs-studio/basic/profiles/*/service.json',
                '~/.terraform.d/credentials.tfrc.json', '~/.vault-token')


def unencrypted_key(p):
    return text(p).startswith('-----BEGIN') and 'ENCRYPTED' not in text(p)[:200] and \
        sh('ssh-keygen', '-y', '-P', '', '-f', p, timeout=5).startswith(('ssh-', 'ecdsa-', 'sk-'))


@check('Secrets and permissions', 'Protection')
def perms():
    home = os.stat(HOME).st_mode
    if home & 0o007: yield warn(f'Your home folder is open to other users (mode {stat.filemode(home)})', f'chmod 700 {HOME}')
    ssh = os.path.expanduser('~/.ssh')
    if os.path.isdir(ssh) and os.stat(ssh).st_mode & 0o077: yield alert(f'~/.ssh is readable by others', 'chmod 700 ~/.ssh')
    for f in files(*SECRET_FILES, '~/.ssh/*', '~/.gnupg'):
        if f.endswith('.pub') or os.path.islink(f) or f.endswith(('known_hosts', 'known_hosts.old')): continue
        m = os.stat(f).st_mode
        if m & 0o077: yield warn(f'{f} holds secrets and is readable by others ({stat.filemode(m)})', f'chmod {700 if os.path.isdir(f) else 600} {f}')
    if os.path.exists(os.path.expanduser('~/.git-credentials')):
        yield warn('Git keeps passwords/tokens in plain text (~/.git-credentials)', 'git config --global credential.helper libsecret, then delete the file')
    if 'oauth_token:' in text(os.path.expanduser('~/.config/gh/hosts.yml')):
        yield warn('GitHub CLI token is stored in plain text', 'gh auth logout && gh auth login (uses the system keyring)')
    if fz := [os.path.basename(f) for f in files('~/.config/filezilla/*.xml') if 'encoding="base64"' in text(f)]:
        yield warn(f'FileZilla keeps FTP/SFTP passwords readable as plain text ({", ".join(fz)})',
                   'FileZilla: Edit > Settings > Interface > Passwords > Use a master password')
    bare = [os.path.basename(p) for p in files('~/.ssh/*') if os.path.isfile(p) and unencrypted_key(p)]
    if bare: yield warn(f'{len(bare)} SSH private key(s) have no passphrase: anything that reads them can log in as you: {", ".join(bare)}',
                        'ssh-keygen -p -f ~/.ssh/<key> to add one (ssh-agent keeps it convenient)')
    for d in os.environ.get('PATH', '').split(':'):
        if d in ('', '.'): yield warn('PATH includes the current directory', 'Remove "." and empty entries from PATH in your shell rc'); continue
        try: m = os.stat(d).st_mode
        except OSError: continue
        if m & 0o002 and not m & stat.S_ISVTX: yield alert(f'PATH folder {d} is writable by every user', f'sudo chmod o-w {d}')


@check('Setuid programs', 'Protection')
def setuid():
    # A new setuid-root binary is the classic way to keep root. Inventory, alert on ones outside system folders.
    out = sh('find', '/', '/home', '/opt', '/var', '-xdev', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-type', 'f', '-print', timeout=120)
    for f in sorted(set(lines(out))):
        try: kind = 'setuid' if os.stat(f).st_mode & stat.S_ISUID else 'setgid'
        except OSError: continue
        if f.startswith(('/home/', '/tmp/', '/var/tmp/', '/dev/shm/')): yield alert(f'{kind} program in a user folder: {f}', f'Check it, then sudo chmod u-s,g-s {f}')
        else: yield item(f'{kind}: {f}')
    for l in lines(sh('getcap', '-r', '/usr/bin', '/usr/sbin', '/usr/local', '/opt', timeout=60)): yield item(f'capabilities: {l}')


NO_SANDBOX = {'--no-sandbox': 'its sandbox off', '--disable-seccomp-filter-sandbox': 'its system-call filter off',
              '--disable-web-security': 'web security (same-origin policy) off'}


def argv(pid):
    # Electron/Chromium rewrite their argv into one space-separated string; a shell's `-c` script stays one argument.
    a = text(f'/proc/{pid}/cmdline').rstrip('\0').split('\0')
    return a[0].split() if len(a) == 1 else a


@check('App sandboxes', 'Protection')
def sandboxes():
    # A Chromium/Electron app (Discord, VS Code, Claude, Slack...) without its sandbox hands any page or message it renders
    # a shot at your whole account. Flatpak apps keep the Flatpak sandbox, so they are skipped.
    seen = {}
    for pid in filter(str.isdigit, os.listdir('/proc')):
        bad = [NO_SANDBOX[a] for a in argv(pid) if a in NO_SANDBOX]
        if not bad or os.path.exists(f'/proc/{pid}/root/.flatpak-info'): continue
        try: exe = os.readlink(f'/proc/{pid}/exe').removesuffix(' (deleted)')
        except OSError: continue
        seen.setdefault(exe, set()).update(bad)
    for exe, why in sorted(seen.items()):
        yield warn(f'{os.path.basename(exe)} runs with {" and ".join(sorted(why))} ({exe})',
                   'Start it without --no-sandbox; for an AppImage or packaged Electron app, check its chrome-sandbox is root-owned '
                   'and setuid (chmod 4755) or that unprivileged user namespaces are enabled')
