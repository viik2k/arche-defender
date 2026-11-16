#!/usr/bin/env python3
# Arche Defender (Linux): one-window sweep of the usual persistence and tampering spots, diffed against a saved baseline.
# Read-only: it never deletes, kills or changes anything. The only file it writes is baseline.json beside itself.
# No root, no dependencies beyond Python 3 with tkinter. Usage: arche-defender.py, or arche-defender.py --selftest
import glob, json, os, re, subprocess, sys, time
from pathlib import Path

BASE_FILE = Path(__file__).resolve().with_name('baseline.json')
HOME = str(Path.home())
SENSITIVE = 'sudo|su|ssh|pkexec|passwd|doas|run0'
RC_FILES = ('~/.bashrc', '~/.bash_profile', '~/.bash_login', '~/.profile', '~/.zshrc', '~/.zprofile', '~/.bashrc.d/*',
            '~/.config/fish/config.fish', '~/.config/environment.d/*.conf', '/etc/environment')


def alert(t): return (str(t), True)    # always bad
def item(t): return (str(t), False)    # inventory: flagged only when not in the baseline
def ver(s): return re.sub(r'\d+(\.\d+){2,}', '*', s)   # app updates must not look like new items


def sh(*cmd, err=False):
    try: return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT if err else subprocess.DEVNULL,
                               text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired): return ''


def text(p):
    try: return Path(p).read_text(errors='replace')
    except OSError: return ''


def lines(s): return [l.strip() for l in s.splitlines() if l.strip() and not l.lstrip().startswith('#')]
def files(*pats): return sorted({p for pat in pats for p in glob.glob(os.path.expanduser(pat))})


def jsonf(p):
    try: return json.loads(text(p))
    except ValueError: return {}


def security():
    fw = sh('systemctl', 'is-active', 'firewalld').strip()
    if fw != 'active': yield alert(f'Firewall (firewalld) is {fw or "missing"}')
    for db in files('/usr/lib/sysimage/rpm/rpmdb.sqlite', '/var/lib/rpm/rpmdb.sqlite')[:1]:
        age = int((time.time() - os.path.getmtime(db)) / 86400)
        if age > 14: yield alert(f'No package updates in {age} days')
    yield item('SELinux: ' + (sh('getenforce').strip() or 'not installed'))
    sb = sh('mokutil', '--sb-state').strip()
    if sb: yield item(sb)


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
    out = sh('rpm', '-qf', *plain, err=True) if plain else ''
    for m in re.finditer(r'file (.+?)(?: is not owned by any package|: No such file or directory)$', out, re.M):
        yield item(ver(f'Not from a package: {m[1]}'))   # /app/... is a Flatpak


def listeners():
    # Keyed by process, not port. Loopback and ephemeral ports (Tailscale, Steam pick new ones every start) skipped.
    for l in sh('ss', '-tlnpH').splitlines():
        f = l.split()
        if len(f) < 4: continue
        addr, _, port = f[3].rpartition(':')
        if re.match(r'^(127\.|\[?::1\]?$)', addr) or addr.endswith('%lo') or not port.isdigit() or int(port) >= 32768: continue
        m = re.search(r'\(\("([^"]+)"', l)
        yield item(m[1] if m else f'port {port} (owned by another user)')


def startup():
    for f in files('~/.config/autostart/*.desktop', '/etc/xdg/autostart/*.desktop'):
        t = text(f); ex = re.search(r'^Exec=(.*)$', t, re.M)
        if ex: yield item(ver(f'{f} -> {ex[1]}' + (' (disabled)' if re.search(r'^Hidden=true', t, re.M) else '')))
    for f in files('~/.config/plasma-workspace/env/*', '~/.config/plasma-workspace/shutdown/*', '~/.config/autostart-scripts/*', '/etc/profile.d/*'):
        yield item(f'Script: {f}')
    for f in files(*RC_FILES):
        for l in lines(text(f)): yield item(f'{f}: {l}')


def scheduled():
    for user in ([], ['--user']):
        out = sh('systemctl', *user, 'list-timers', '--all', '-o', 'json')
        for t in json.loads(out or '[]'): yield item(f'Timer: {t["unit"]} -> {t["activates"]}')
    for l in lines(sh('crontab', '-l')): yield item(f'crontab: {l}')
    for f in files('/etc/crontab', '/etc/anacrontab', '/etc/cron.d/*'):
        for l in lines(text(f)): yield item(f'{f}: {l}')
    for f in files('/etc/cron.hourly/*', '/etc/cron.daily/*', '/etc/cron.weekly/*', '/etc/cron.monthly/*'): yield item(f'Script: {f}')


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


def network():
    for l in lines(text('/etc/hosts')): yield item('hosts: ' + ' '.join(l.split()))
    dns = {s for l in sh('resolvectl', 'dns').splitlines() for s in l.partition(': ')[2].split()}
    for s in sorted(dns or re.findall(r'^nameserver\s+(\S+)', text('/etc/resolv.conf'), re.M)): yield item(f'DNS server: {s}')
    for k in ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        if os.environ.get(k): yield item(f'Proxy ({k}): {os.environ[k]}')
    kio = text(f'{HOME}/.config/kioslaverc')
    if re.search(r'^ProxyType=[1-9]', kio, re.M):
        for m in re.finditer(r'^(ProxyType|\w*[pP]roxy|Proxy Config Script)=(.+)$', kio, re.M): yield item(f'KDE proxy {m[1]}: {m[2]}')


REMOTE = {'sshd', 'sshd-session', 'xrdp', 'krdpserver', 'x11vnc', 'wayvnc', 'Xvnc', 'rustdesk', 'anydesk', 'teamviewerd', 'sunshine'}


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
    for m in sh('getent', 'group', 'wheel').strip().rpartition(':')[2].split(','):
        if m: yield item(f'Admin (wheel): {m}')


CHROMIUM = (('Chrome', 'google-chrome', 'com.google.Chrome'), ('Chromium', 'chromium', 'org.chromium.Chromium'),
            ('Edge', 'microsoft-edge', 'com.microsoft.Edge'), ('Brave', 'BraveSoftware/Brave-Browser', 'com.brave.Browser'),
            ('Vivaldi', 'vivaldi', 'com.vivaldi.Vivaldi'), ('Helium', 'net.imput.helium', 'net.imput.helium'))


def browsers():
    hosts = ['/etc/opt/chrome/native-messaging-hosts', '/etc/chromium/native-messaging-hosts', '/etc/opt/edge/native-messaging-hosts',
             '~/.mozilla/native-messaging-hosts', '/usr/lib64/mozilla/native-messaging-hosts', '/usr/lib/mozilla/native-messaging-hosts']
    for name, sub, flat in CHROMIUM:
        for root in (f'{HOME}/.config/{sub}', f'{HOME}/.var/app/{flat}/config/{sub}'):
            hosts.append(f'{root}/NativeMessagingHosts')
            for mf in files(f'{root}/*/Extensions/*/*/manifest.json'):
                j, d = jsonf(mf), os.path.dirname(mf)
                title = j.get('name', '?')
                if m := re.match(r'^__MSG_(.+)__$', title):
                    for loc in files(*(f'{d}/_locales/{x}/messages.json' for x in ('en', 'en_US', 'en_GB')))[:1]:
                        msgs = {k.lower(): v for k, v in jsonf(loc).items()}
                        title = msgs.get(m[1].lower(), {}).get('message') or title
                wide = ' (all sites)' if re.search(r'<all_urls>|\*://\*/|https?://\*/', f'{j.get("permissions")} {j.get("host_permissions")}') else ''
                yield item(f'{name}: {title} [{Path(d).parent.name}]{wide}')
    for ext in files('~/.mozilla/firefox/*/extensions.json', '~/.config/mozilla/firefox/*/extensions.json',
                     '~/.var/app/org.mozilla.firefox/.mozilla/firefox/*/extensions.json'):
        for a in jsonf(ext).get('addons', []):
            if a.get('location') == 'app-profile': yield item(f'Firefox: {(a.get("defaultLocale") or {}).get("name")} [{a.get("id")}]')
    for h in files(*(f'{d}/*.json' for d in hosts)):
        yield item(ver(f'Native host: {Path(h).stem} -> {jsonf(h).get("path")}'))


def modules():
    # ponytail: out-of-tree/unsigned modules are inventory, not alerts: the NVIDIA driver is both on a stock Nobara install.
    for l in text('/proc/modules').splitlines():
        m = l.split()[0]; t = text(f'/sys/module/{m}/taint')
        if 'O' in t or 'E' in t: yield item(f'{m} ({"out-of-tree" if "O" in t else "in-tree"}{", unsigned" if "E" in t else ""})')


CHECKS = {'Security posture': security, 'Running programs': running, 'Network listeners': listeners,
          'Startup entries': startup, 'Scheduled tasks': scheduled, 'Services': services, 'Hijack points': hijack,
          'Network settings': network, 'Remote access and accounts': remote, 'Browser extensions': browsers,
          'Kernel modules': modules}


def load_baseline(): return jsonf(BASE_FILE) if BASE_FILE.exists() else None


def run_check(name, base):
    """One check -> sorted (text, alert, new) rows; new = not an alert and not in the baseline."""
    try: rows = list(CHECKS[name]())
    except Exception as e: rows = [alert(f'Check failed: {e!r}')]
    merged = {}
    for t, a in rows:
        if t: merged[t] = merged.get(t, False) or a
    known = set((base or {}).get(name, []))
    return [(t, a, base is not None and not a and t not in known) for t, a in sorted(merged.items())]


def selftest():
    fail = 0
    if ver('/x/app-1.0.9267/a') != '/x/app-*/a': print('FAIL ver'); fail += 1
    CHECKS['_t'] = lambda: [item('known'), item('fresh'), alert('bad'), item('fresh')]
    r = run_check('_t', {'_t': ['known']})
    if [t for t, a, n in r if n] != ['fresh'] or [t for t, a, n in r if a] != ['bad']: print('FAIL baseline diff'); fail += 1
    del CHECKS['_t']
    for n in CHECKS:
        r = run_check(n, None)
        print(f'{n:<28} {len(r):3} rows, {sum(a for _, a, _ in r)} alerts')
        for t, a, _ in r:
            if a: print(f'    [!] {t}')
    print('self-test FAILED' if fail else 'self-test passed')
    sys.exit(1 if fail else 0)


def gui():
    import tkinter as tk
    BG, PANEL, FG, MUTED = '#14161a', '#1b1e23', '#e8eaed', '#9aa0a6'
    RED, AMBER, GREEN = '#ff6b6b', '#f5c451', '#7bd88f'
    root = tk.Tk(className='arche-defender')
    root.title('Arche Defender'); root.geometry('1040x640'); root.configure(bg=BG)
    top = tk.Frame(root, bg=BG); top.pack(fill='x', padx=14, pady=(14, 12))
    tk.Label(top, text='ARCHE DEFENDER', bg=BG, fg=FG, font=('TkDefaultFont', 16, 'bold')).pack(side='left')
    flat = dict(relief='flat', bd=0, padx=18, pady=6, highlightthickness=0, cursor='hand2')
    scan = tk.Button(top, text='Scan', bg='#2f6f4f', fg='white', activebackground='#3a8560', activeforeground='white',
                     font=('TkDefaultFont', 10, 'bold'), **flat)
    scan.pack(side='right')
    save = tk.Button(top, text='Accept as baseline', bg='#2a2e35', fg=FG, activebackground='#3a3f47', activeforeground=FG, **flat)
    save.pack(side='right', padx=8)
    status = tk.Label(root, bg=BG, fg=MUTED, anchor='w'); status.pack(side='bottom', fill='x', padx=14, pady=(0, 10))
    body = tk.Frame(root, bg=BG); body.pack(fill='both', expand=True, padx=14)
    lst = tk.Listbox(body, width=34, bg=PANEL, fg=FG, selectbackground='#2a2e35', highlightthickness=0, bd=0,
                     activestyle='none', font=('TkDefaultFont', 11), exportselection=False)
    lst.pack(side='left', fill='y', padx=(0, 10))
    det = tk.Text(body, bg=PANEL, fg='#cfd3d8', bd=0, highlightthickness=0, wrap='word', font=('monospace', 10), padx=8, pady=8)
    bar = tk.Scrollbar(body, command=det.yview, bg=PANEL, troughcolor=BG, bd=0, highlightthickness=0, elementborderwidth=0)
    det.config(yscrollcommand=bar.set)
    bar.pack(side='right', fill='y'); det.pack(side='left', fill='both', expand=True)
    det.tag_configure('alert', foreground=RED); det.tag_configure('new', foreground=AMBER)
    names, last = list(CHECKS), {}

    def show(_=None):
        sel = lst.curselection()
        rows = last.get(names[sel[0]]) if sel else None
        det.config(state='normal'); det.delete('1.0', 'end')
        if not rows: det.insert('end', 'Nothing to report.')
        for t, a, n in rows or []:
            det.insert('end', ('[!] ' if a else '[+] ' if n else '    ') + t + '\n', 'alert' if a else 'new' if n else '')
        det.config(state='disabled')

    def do_scan():
        scan.config(state='disabled'); lst.delete(0, 'end'); last.clear(); show()
        base = load_baseline(); alerts = new = 0
        for i, n in enumerate(names):
            status.config(text=f'Scanning: {n} ...')
            # ponytail: checks run on the UI thread, pumped between checks so the list fills in. Move to a thread if a check gets slow.
            root.update()
            r = last[n] = run_check(n, base)
            a, w = sum(x[1] for x in r), sum(x[2] for x in r); alerts += a; new += w
            lst.insert('end', f'!!   {n}  ({a} alert)' if a else f'+    {n}  ({w} new)' if w else f'ok   {n}  ({len(r)})')
            c = RED if a else AMBER if w else GREEN
            lst.itemconfig(i, fg=c, selectforeground=c)
        status.config(text=time.strftime('%H:%M:%S') + f'  {alerts} alerts, {new} new since baseline.'
                      + ('' if base is not None else '  No baseline yet: review the lists, then Accept as baseline.'))
        scan.config(state='normal')
        lst.selection_set(next((i for i in range(len(names)) if not lst.get(i).startswith('ok')), 0)); show()

    def do_save():
        if not last: return
        BASE_FILE.write_text(json.dumps({n: [t for t, a, _ in last[n] if not a] for n in names}, indent=2))
        BASE_FILE.chmod(0o600)   # it lists what is on this machine
        do_scan()

    lst.bind('<<ListboxSelect>>', show)
    scan.config(command=do_scan); save.config(command=do_save)
    root.after(100, do_scan)
    root.mainloop()


if __name__ == '__main__':
    selftest() if '--selftest' in sys.argv else gui()
