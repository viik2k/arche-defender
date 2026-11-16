# Persistence and tampering sweep: the places malware hides to survive a reboot, plus what is exposed right now.
import glob, json, os, re
from pathlib import Path
from .core import HOME, PKG, alert, warn, item, ver, sh, have, text, lines, files, jsonf, check, owned

SENSITIVE = 'sudo|su|ssh|pkexec|passwd|doas|run0'
RC_FILES = ('~/.bashrc', '~/.bash_profile', '~/.bash_login', '~/.profile', '~/.zshrc', '~/.zprofile', '~/.bashrc.d/*',
            '~/.zshenv', '~/.zlogin', '~/.bash_logout', '~/.xprofile', '~/.xinitrc', '~/.xsession', '~/.xsessionrc',
            '~/.config/fish/config.fish', '~/.config/fish/conf.d/*.fish', '~/.config/environment.d/*.conf', '/etc/environment')
APPS = ('/usr/share/applications', '/usr/local/share/applications', '/var/lib/flatpak/exports/share/applications',
        '~/.local/share/flatpak/exports/share/applications')
GIT_RUNS = re.compile(r'^(core\.(sshcommand|hookspath|pager|askpass)|filter\..+\.(clean|smudge|process)|diff\..+\.(textconv|command)|'
                      r'merge\..+\.driver|gpg(\.\w+)?\.program)$')
OFF = ('true', 'false', 'yes', 'no', 'on', 'off', '1', '0', '')


def git_runs(listing):
    """(key, value) for each line of `git config -l` that makes git run a command (Git LFS's own filter left out)."""
    for k, v in re.findall(r'^([^=\n]+)=(.*)$', listing, re.M):
        if (GIT_RUNS.match(k) and not v.startswith(('git-lfs ', 'git lfs '))) or (k == 'core.fsmonitor' and v.lower() not in OFF) or (
                k.startswith('alias.') or k.endswith('.helper')) and v.startswith('!'): yield k, v


@check('Running programs', 'Processes')
def running():
    exes = set()
    for p in glob.glob('/proc/[0-9]*/exe'):
        try: exes.add(os.readlink(p))
        except OSError: pass   # ponytail: other users' processes (root daemons) are unreadable without root
    drop = re.compile(rf'^(/tmp/|/var/tmp/|/dev/shm/|/memfd:|{re.escape(HOME)}/Downloads/)')
    plain = []
    for e in sorted(exes):
        if drop.match(e): yield alert(f'Running from a drop folder: {e}')
        elif e.endswith(' (deleted)'): yield item(ver(f'Running a replaced binary (restart it after updates): {e}'))
        else: plain.append(e)
    if PKG:
        for e in sorted(set(plain) - owned(plain)): yield item(ver(f'Not from a package: {e}'))   # /app/... is a Flatpak


@check('Network listeners', 'Network')
def listeners():
    # Keyed by process, not port. Loopback and ephemeral ports (Tailscale, Steam pick new ones every start) skipped.
    for l in sh('ss', '-tlnpH').splitlines():
        f = l.split()
        if len(f) < 4: continue
        addr, _, port = f[3].rpartition(':')
        if re.match(r'^(127\.|\[?::1\]?$)', addr) or addr.endswith('%lo') or not port.isdigit() or int(port) >= 32768: continue
        m = re.search(r'\(\("([^"]+)"', l)
        yield item(m[1] if m else f'port {port} (owned by another user)')


@check('Startup entries', 'Persistence')
def startup():
    for f in files('~/.config/autostart/*.desktop', '/etc/xdg/autostart/*.desktop'):
        t = text(f); ex = re.search(r'^Exec=(.*)$', t, re.M)
        if ex: yield item(ver(f'{f} -> {ex[1]}' + (' (disabled)' if re.search(r'^Hidden=true', t, re.M) else '')))
    for f in files('~/.config/plasma-workspace/env/*', '~/.config/plasma-workspace/shutdown/*', '~/.config/autostart-scripts/*', '/etc/profile.d/*'):
        yield item(f'Script: {f}')
    for f in files(*RC_FILES):
        for l in lines(text(f)): yield item(f'{f}: {l}')


@check('Scheduled tasks', 'Persistence')
def scheduled():
    for user in ([], ['--user']):
        out = sh('systemctl', *user, 'list-timers', '--all', '-o', 'json')
        for t in json.loads(out or '[]'): yield item(f'Timer: {t["unit"]} -> {t["activates"]}')
    for l in lines(sh('crontab', '-l')): yield item(f'crontab: {l}')
    for f in files('/etc/crontab', '/etc/anacrontab', '/etc/cron.d/*'):
        for l in lines(text(f)): yield item(f'{f}: {l}')
    for f in files('/etc/cron.hourly/*', '/etc/cron.daily/*', '/etc/cron.weekly/*', '/etc/cron.monthly/*'): yield item(f'Script: {f}')


@check('Services', 'Persistence')
def services():
    # Units from packages live in /usr; /run holds desktop app launches and autostart copies. The rest was added by hand.
    for user in ([], ['--user']):
        units = [u['unit'] for u in json.loads(sh('systemctl', *user, 'list-units', '--all', '--type=service', '-o', 'json') or '[]')]
        for block in sh('systemctl', *user, 'show', '-p', 'Id,FragmentPath,ExecStart', *units).split('\n\n') if units else []:
            p = dict(l.split('=', 1) for l in block.splitlines() if '=' in l)
            frag = p.get('FragmentPath', '')
            if not frag or frag.startswith(('/usr/', '/run/', '/dev/')): continue
            argv = re.search(r'argv\[\]=(.*?) ;', p.get('ExecStart', ''))
            yield item(ver(f'{p["Id"]} [{"user" if user else "system"}] -> {argv[1] if argv else frag}'))
    # Drop-ins (<unit>.d/*.conf) change a packaged unit without touching its file: an ExecStartPre= there runs before it starts,
    # and one in service.d/ before every service. Package files are left out; drop-ins that only tune resources are too.
    ins = files(*(f'{d}/*.d/*.conf' for d in ('/etc/systemd/system', '/etc/systemd/user', '~/.config/systemd/user', '~/.local/share/systemd/user')))
    for f in sorted(set(ins) - owned(ins)):
        if ex := re.findall(r'^[ \t]*(Exec\w+=[ \t]*\S.*)$', text(f), re.M):
            unit = os.path.basename(os.path.dirname(f))[:-2]
            yield item(ver(f'{f} adds to {unit if "." in unit else "every " + unit}: {"; ".join(ex)[:200]}'))


@check('Hijack points', 'Persistence')
def hijack():
    for l in lines(text('/etc/ld.so.preload')): yield alert(f'/etc/ld.so.preload: {l}')
    for f in files('/etc/environment', '~/.config/environment.d/*.conf', '/etc/environment.d/*.conf'):
        for l in lines(text(f)):
            if re.search(r'\bLD_(PRELOAD|LIBRARY_PATH|AUDIT)\b', l): yield alert(f'{f}: {l}')
    for f in files(*(f'{d}/{c}' for d in ('~/.local/bin', '~/bin', '~/.cargo/bin', '/usr/local/bin', '/usr/local/sbin') for c in SENSITIVE.split('|'))):
        yield alert(f'Shadows a system command: {f}')
    for f in files(*RC_FILES):
        for l in lines(text(f)):
            if re.match(rf'(alias\s+({SENSITIVE})=|function\s+({SENSITIVE})\b|({SENSITIVE})\s*\(\))', l): yield alert(f'{f} redefines: {l}')
    for f in files('/etc/pam.d/*'):
        for l in lines(text(f)):
            if 'pam_exec' in l: yield alert(f'{f}: {l}')
    for f in files('/etc/udev/rules.d/*.rules'):
        for l in lines(text(f)):
            if 'RUN' in l: yield item(f'{f}: {l}')
    # Root runs these on its own: on every network change, at every boot (generators), whenever a module loads (modprobe install),
    # for every program of a registered binary format (binfmt_misc), at every login message (motd). Package files are left out.
    root = [f for f in files('/etc/NetworkManager/dispatcher.d/*', '/etc/NetworkManager/dispatcher.d/*/*', '/etc/update-motd.d/*',
                             *(f'{d}/systemd/{k}-generators/*' for d in ('/etc', '/usr/local/lib') for k in ('system', 'user')))
            if os.path.isfile(f)]
    for f in sorted(set(root) - owned(root)): yield item(ver(f'Runs as root by itself: {f}'))
    mods = files('/etc/modprobe.d/*.conf', '/usr/lib/modprobe.d/*.conf', '/usr/local/lib/modprobe.d/*.conf')
    for f in sorted(set(mods) - owned(mods)):
        for mod, cmd in install_cmds(text(f)):
            yield alert(f'{f} runs a command as root whenever the {mod} module loads: {cmd[:150]}', f'Inspect it, then remove that install line from {f}')
    fmt = {f: m[1] for f in files('/proc/sys/fs/binfmt_misc/*') if (m := re.search(r'^interpreter (\S+)', text(f), re.M))}
    pkg = owned(set(fmt.values()))
    for f, interp in sorted(fmt.items()):
        if interp in pkg: continue
        yield (alert if interp.startswith(('/tmp/', '/var/tmp/', '/dev/shm/', '/home/')) else item)(
            f'Every program of the {os.path.basename(f)} binary format runs through {interp}', 'Inspect it, then: echo -1 | sudo tee ' + f)


def install_cmds(t):
    """(module, command) for modprobe `install` lines that do more than block the module or load it the normal way."""
    for mod, cmd in re.findall(r'^\s*install\s+(\S+)\s+(.+)$', t, re.M):
        if not re.fullmatch(r'(/usr)?(/s?bin/)?(true|false|exit\s+\d+)', cmd.strip()) and not \
                re.fullmatch(r'(/usr)?/s?bin/modprobe\s+(-\S+\s+)*\S+(\s*(&&|;)\s*(/usr)?/s?bin/modprobe\s+(-\S+\s+)*\S+)*', cmd.strip()):
            yield mod, cmd.strip()


def field(f, k): return next(iter(re.findall(rf'^{k}=(.*)$', text(f), re.M)), '').strip()


@check('Command hooks', 'Persistence')
def hooks():
    """Lesser-known places that run a command for you: D-Bus activation, git, the SSH client, file-manager menus,
    Python start-up and app launchers that replace the system's own."""
    from .ai import redact, repos, scan_text, tilde   # git and ssh values can hold tokens
    sysbus = {field(f, 'Name') for f in files('/usr/share/dbus-1/services/*.service')}
    for f in files('~/.local/share/dbus-1/services/*.service'):
        if field(f, 'Name') in sysbus: yield alert(f'{f} takes over the system D-Bus service {field(f, "Name")}: {field(f, "Exec")}',
                                                   f'Inspect it, then delete {f}')
        else: yield item(f'D-Bus service: {f} -> {field(f, "Exec")}')
    tpl = ['/usr/share/git-core/templates']
    for scope in ('--system', '--global') if have('git') else ():
        conf = sh('git', 'config', scope, '--includes', '-l')
        for k, v in git_runs(conf): yield item(f'git {scope[2:]} {k}: {redact(v)[:150]}')
        tpl += re.findall(r'^init\.templatedir=(.+)$', conf, re.M)
    # git clone and git init copy the template's hooks into the new repo; post-checkout then runs during the clone itself
    for h in files(*(f'{os.path.expanduser(d)}/hooks/*' for d in dict.fromkeys(tpl))):
        if not h.endswith('.sample') and os.access(h, os.X_OK):
            yield item(f'Every repo you clone or create gets this git hook: {tilde(h)}')
            yield from ((t, sev, f'Read it; if you did not add it, delete {tilde(h)}') for t, sev, _ in scan_text(text(h), f'git template hook {tilde(h)}'))
    # A repo's own .git folder is not cloned, but one unpacked from a zip or tarball brings it along: its fsmonitor runs on every
    # `git status`, which shell prompts, editors and AI agents run by themselves the moment you open the folder.
    for r in repos() if have('git') else ():
        for k, v in git_runs(sh('git', 'config', '--file', f'{r}/.git/config', '--includes', '-l')):
            if k == 'core.fsmonitor' and not v.startswith('.git/hooks/'):
                yield warn(f'{tilde(r)} runs a command each time git status runs there (shell prompts, editors and AI agents do that '
                           f'on their own): {redact(v)[:120]}', f'If you did not set it: git -C {tilde(r)} config --unset core.fsmonitor')
            else: yield item(f'git {tilde(r)} {k}: {redact(v)[:150]}')
        for h in files(f'{r}/.git/hooks/*'):
            if not h.endswith('.sample') and os.access(h, os.X_OK):
                yield item(f'Git hook: {tilde(h)}')
                yield from ((t, sev, f'Read it; if you did not add it, delete {tilde(h)}') for t, sev, _ in scan_text(text(h), f'git hook {tilde(h)}'))
    for f in files('~/.ssh/config', '~/.ssh/config.d/*', '/etc/ssh/ssh_config', '/etc/ssh/ssh_config.d/*'):
        for l in lines(text(f)):
            if re.match(r'(?i)(ProxyCommand|LocalCommand|KnownHostsCommand)\b|Match\s.*\bexec\b', l): yield item(f'{f}: {redact(l)[:150]}')
    for f in files('~/.local/share/kio/servicemenus/*.desktop', '~/.local/share/kservices5/ServiceMenus/*.desktop'):
        for x in re.findall(r'^Exec=(.*)$', text(f), re.M): yield item(f'File-manager menu: {f} -> {x}')
    for f in files('~/.local/share/nautilus/scripts/*', '~/.local/share/nemo/actions/*.nemo_action'): yield item(f'File-manager script: {f}')
    for f in files('~/.local/lib/python3*/site-packages/*.pth', '/usr/local/lib*/python3*/site-packages/*.pth'):
        if any(l.startswith('import') for l in text(f).splitlines()): yield item(ver(f'Runs at every Python start: {f}'))
    for f in files('~/.local/lib/python3*/site-packages/*customize.py', '/usr/local/lib*/python3*/site-packages/*customize.py'):
        yield item(ver(f'Runs at every Python start: {f}'))
    if os.environ.get('PYTHONSTARTUP'): yield item(f'Runs at every interactive Python start: {os.environ["PYTHONSTARTUP"]}')
    system = {os.path.basename(f): f for d in APPS for f in files(f'{d}/*.desktop')}
    for f in files('~/.local/share/applications/*.desktop'):
        s = system.get(os.path.basename(f))
        if s and field(f, 'Exec') and field(f, 'Exec') != field(s, 'Exec'):
            yield item(f'Launcher {os.path.basename(f)} replaces the system one and runs: {field(f, "Exec")}')


def dns_rows(st):
    """Whether DNS lookups are encrypted, from `resolvectl status`: the global settings and the links that carry the default route."""
    mode = re.search(r'resolv\.conf mode:\s*(\S+)', st)
    if mode and mode[1] in ('foreign', 'uplink', 'missing'):
        yield item('DNS lookups skip systemd-resolved (/etc/resolv.conf names the servers itself), so they go out unencrypted',
                   'To encrypt them: sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf, then set DNSOverTLS in resolved.conf')
        return
    used = ' '.join(b for b in st.split('\n\n') if b.lstrip().startswith('Global') or '+DefaultRoute' in b)
    if '+DNSOverTLS' in used: yield item('DNS over TLS: on')
    elif 'DNSOverTLS=opportunistic' in used:
        yield item('DNS over TLS: opportunistic (plain DNS whenever the server does not offer it, or something on the network blocks it)')
    elif used: yield item('DNS lookups go out unencrypted: on public Wi-Fi the network can read them and answer with fake sites',
                          'Set DNSOverTLS=opportunistic in /etc/systemd/resolved.conf ("yes" needs a resolver that supports it), '
                          'or turn on secure DNS in your browser')


@check('Network settings', 'Network')
def network():
    for l in lines(text('/etc/hosts')): yield item('hosts: ' + ' '.join(l.split()))
    dns = {s for l in sh('resolvectl', 'dns').splitlines() for s in l.partition(': ')[2].split()}
    for s in sorted(dns or re.findall(r'^nameserver\s+(\S+)', text('/etc/resolv.conf'), re.M)): yield item(f'DNS server: {s}')
    yield from dns_rows(sh('resolvectl', 'status'))
    for k in ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        if os.environ.get(k): yield item(f'Proxy ({k}): {os.environ[k]}')
    kio = text(f'{HOME}/.config/kioslaverc')
    if re.search(r'^ProxyType=[1-9]', kio, re.M):
        for m in re.finditer(r'^(ProxyType|\w*[pP]roxy|Proxy Config Script)=(.+)$', kio, re.M): yield item(f'KDE proxy {m[1]}: {m[2]}')


REMOTE = {'sshd', 'sshd-session', 'xrdp', 'krdpserver', 'x11vnc', 'wayvnc', 'Xvnc', 'rustdesk', 'anydesk', 'teamviewerd', 'sunshine'}


@check('Remote access and accounts', 'Network')
def remote():
    for c in sorted({text(p).strip() for p in glob.glob('/proc/[0-9]*/comm')} & REMOTE): yield item(f'Running: {c}')
    for f in files('~/.ssh/authorized_keys', '~/.ssh/authorized_keys2'):
        for l in lines(text(f)):
            m = re.search(r'((?:ssh|ecdsa|sk)-\S+)\s+(\S+)\s*(.*)', l)
            if m: yield item(f'SSH key accepted: {l[:m.start()]}{m[1]} ...{m[2][-12:]} {m[3]}'.rstrip())
    for f in files('~/.ssh/rc'): yield item(f'Runs on every SSH login: {f}')
    for s in re.findall(r'^\s*\[([^\]]+)\]', text('/etc/samba/smb.conf'), re.M):
        if s.lower() not in ('global', 'homes', 'printers', 'print$'): yield item(f'Samba share: {s}')
    for l in lines(text('/etc/exports')): yield item(f'NFS export: {l}')
    for l in text('/etc/passwd').splitlines():
        f = l.split(':')
        if len(f) < 7 or not f[2].isdigit(): continue
        if f[2] == '0' and f[0] != 'root': yield alert(f'Second root account (uid 0): {f[0]}')
        elif int(f[2]) >= 1000 and not f[6].endswith(('nologin', 'false')): yield item(f'Login account: {f[0]} ({f[6]})')
    for g in ('wheel', 'sudo', 'admin'):   # Fedora/Arch, Debian/Ubuntu, old Ubuntu
        for m in sh('getent', 'group', g).strip().rpartition(':')[2].split(','):
            if m: yield item(f'Admin ({g}): {m}')
    for g in ('docker', 'lxd', 'libvirt', 'disk'):   # root without sudo: mount / into a container or VM, or write the raw disk
        for m in sh('getent', 'group', g).strip().rpartition(':')[2].split(','):
            if m: yield warn(f'{m} is in the {g} group: any program {m} runs can make itself root, with no password',
                             f'If you do not need it: sudo gpasswd -d {m} {g}' + (' (rootless Docker or Podman does the job without it)' if g == 'docker' else ''))


CHROMIUM = (('Chrome', 'google-chrome', 'com.google.Chrome'), ('Chromium', 'chromium', 'org.chromium.Chromium'),
            ('Edge', 'microsoft-edge', 'com.microsoft.Edge'), ('Brave', 'BraveSoftware/Brave-Browser', 'com.brave.Browser'),
            ('Vivaldi', 'vivaldi', 'com.vivaldi.Vivaldi'), ('Helium', 'net.imput.helium', 'net.imput.helium'))


def chromium_roots():
    """(browser, user-data-dir) for every Chromium-family browser, plus any other dir laid out like one (a second Brave
    started with --user-data-dir=~/.config/brave-vault). Electron apps keep Preferences at their root, so they stay out."""
    roots = [(n, r) for n, sub, flat in CHROMIUM for r in (f'{HOME}/.config/{sub}', f'{HOME}/.var/app/{flat}/config/{sub}')]
    known = {os.path.realpath(r) for _, r in roots}
    for ls in files('~/.config/*/Local State', '~/.var/app/*/config/*/Local State'):
        d = os.path.dirname(ls)
        if os.path.realpath(d) not in known and files(f'{d}/Default/Preferences', f'{d}/Profile */Preferences'):
            known.add(os.path.realpath(d)); roots.append((os.path.basename(d), d))
    return roots


def chromium_extensions():
    """(browser, title, extension id, manifest) for every Chromium-family extension installed for this user, also the ones
    loaded from a folder (developer mode or --load-extension), which live outside Extensions/."""
    for name, root in chromium_roots():
        found = [(mf, Path(mf).parent.parent.name) for mf in files(f'{root}/*/Extensions/*/*/manifest.json')]
        for pref in files(f'{root}/*/Preferences'):
            st = {}   # Chrome keeps them in Secure Preferences, Brave and others in Preferences
            for f in ('Preferences', 'Secure Preferences'): st.update((jsonf(f'{os.path.dirname(pref)}/{f}').get('extensions') or {}).get('settings') or {})
            found += [(f'{v["path"]}/manifest.json', eid) for eid, v in st.items()
                      if isinstance(v, dict) and v.get('location') in (4, 8) and os.path.isfile(f'{v.get("path")}/manifest.json')]
        for mf, eid in found:
            j, d = jsonf(mf), os.path.dirname(mf)
            title = j.get('name', '?')
            if m := re.match(r'^__MSG_(.+)__$', title):
                for loc in files(*(f'{d}/_locales/{x}/messages.json' for x in ('en', 'en_US', 'en_GB')))[:1]:
                    msgs = {k.lower(): v for k, v in jsonf(loc).items()}
                    title = msgs.get(m[1].lower(), {}).get('message') or title
            yield name, title, eid, j


def firefox_addons():
    """extensions.json entries for the add-ons this user installed in Firefox."""
    for ext in files('~/.mozilla/firefox/*/extensions.json', '~/.config/mozilla/firefox/*/extensions.json',
                     '~/.var/app/org.mozilla.firefox/.mozilla/firefox/*/extensions.json'):
        yield from (a for a in jsonf(ext).get('addons', []) if isinstance(a, dict) and a.get('location') == 'app-profile')


@check('Browser extensions', 'Persistence')
def browsers():
    hosts = ['/etc/opt/chrome/native-messaging-hosts', '/etc/chromium/native-messaging-hosts', '/etc/opt/edge/native-messaging-hosts',
             '~/.mozilla/native-messaging-hosts', '/usr/lib64/mozilla/native-messaging-hosts', '/usr/lib/mozilla/native-messaging-hosts']
    hosts += [f'{r}/NativeMessagingHosts' for _, r in chromium_roots()]
    for name, title, eid, j in chromium_extensions():
        wide = ' (all sites)' if re.search(r'<all_urls>|\*://\*/|https?://\*/', f'{j.get("permissions")} {j.get("host_permissions")}') else ''
        yield item(f'{name}: {title} [{eid}]{wide}')
    for a in firefox_addons(): yield item(f'Firefox: {(a.get("defaultLocale") or {}).get("name")} [{a.get("id")}]')
    for h in files(*(f'{d}/*.json' for d in hosts)):
        yield item(ver(f'Native host: {Path(h).stem} -> {jsonf(h).get("path")}'))


@check('Kernel modules', 'Persistence')
def modules():
    # ponytail: out-of-tree/unsigned modules are inventory, not alerts: the NVIDIA driver is both on a stock Nobara install.
    for l in text('/proc/modules').splitlines():
        m = l.split()[0]; t = text(f'/sys/module/{m}/taint')
        if 'O' in t or 'E' in t: yield item(f'{m} ({"out-of-tree" if "O" in t else "in-tree"}{", unsigned" if "E" in t else ""})')
