# Privacy and devices: what can see or hear you right now, what sandboxed apps are allowed to touch,
# and the hardware that is plugged in or paired (a new "keyboard" can be a BadUSB).
import configparser, grp, json, os, re
from .core import check, alert, warn, item, sh, have, text, files, HOME
from .ai import secret_kinds
from .malware import walk


def comm(pid): return text(f'/proc/{pid}/comm').strip() or f'pid {pid}'


def pipewire_streams():
    """(media.class, app name, node name) for every PipeWire stream and video source."""
    try: objs = json.loads(sh('pw-dump', timeout=10) or '[]')
    except ValueError: return []
    out = []
    for o in objs:
        p = ((o.get('info') or {}).get('props') or {})
        mc = p.get('media.class', '')
        if mc.startswith(('Stream/Input', 'Video/Source')):
            out.append((mc, p.get('application.name') or p.get('application.process.binary') or p.get('node.name', '?'), p.get('node.name', '')))
    return out


@check('Camera, microphone and screen', 'Privacy')
def watching():
    """Apps that have the camera, a microphone, a screen capture or the keyboard open at the moment of the scan."""
    for fd in files('/proc/[0-9]*/fd/*'):
        try:
            if re.match(r'/dev/video\d+$', os.readlink(fd)): yield item(f'Camera open by {comm(fd.split("/")[2])}')
        except OSError: pass   # ponytail: other users' processes need root
    opened = []
    for fd in files('/proc/[0-9]*/fd/*'):
        try: dev = os.readlink(fd)
        except OSError: continue
        if re.match(r'/dev/input/event\d+$|/dev/uinput$', dev): opened.append((comm(fd.split('/')[2]), dev))
    try: in_group = grp.getgrnam('input').gr_gid in os.getgroups()
    except KeyError: in_group = False
    yield from input_rows(opened, keyboards(text('/proc/bus/input/devices')), in_group)
    for mc, app, node in pipewire_streams():
        if mc.endswith('/Internal'): continue
        if mc.startswith('Stream/Input/Audio'): yield item(f'Microphone open by {app}')
        elif mc.startswith('Stream/Input/Video'): yield item(f'Camera or screen capture open by {app}')
        elif 'portal' in node.lower() or 'screen' in node.lower(): yield item(f'Screen is being shared ({app})')


# Desktop sessions get keyboards through logind; the rest are remappers, macro and game-streaming tools users install.
COMPOSITORS = {'kwin_wayland', 'Xorg', 'Xwayland', 'gnome-shell', 'mutter', 'sway', 'Hyprland', 'weston', 'labwc', 'niri', 'cosmic-comp',
               'river', 'wayfire', 'gamescope', 'systemd-logind'}
INPUT_TOOLS = {'steam', 'steamwebhelper', 'input-remapper', 'input-remapper-s', 'keyd', 'kanata', 'kmonad', 'xremap', 'espanso', 'sunshine',
               'solaar', 'antimicrox', 'ydotoold', 'evsieve', 'warpd', 'showmethekey-cli', 'evtest', 'libinput', 'openrgb', 'rustdesk'}


def keyboards(devices):
    """{'eventN': name} for real keyboards in /proc/bus/input/devices (key repeat on: not power buttons or speakers)."""
    out = {}
    for b in devices.split('\n\n'):
        name, h, ev = re.search(r'^N: Name="(.*)"', b, re.M), re.search(r'^H: Handlers=(.*)$', b, re.M), re.search(r'^B: EV=(\w+)', b, re.M)
        if name and h and ev and 'kbd' in h[1].split() and int(ev[1], 16) & 0x100000:
            out |= {e: name[1] for e in h[1].split() if e.startswith('event')}
    return out


def input_rows(opened, kbds, in_group):
    """opened: (process, device path). A program that holds a keyboard sees every key typed in every app;
    one that holds /dev/uinput can type and click as you."""
    if in_group: yield warn('Your account is in the input group: every program you run can read your keystrokes',
                            fix='Unless a remapper needs it: sudo gpasswd -d $USER input (then log out and back in)')
    for proc, dev in sorted(set(opened)):
        if proc in COMPOSITORS: continue
        what = f'reads your keyboard ({kbds[dev[11:]]})' if dev[11:] in kbds else 'can type and click as you (/dev/uinput)' if dev == '/dev/uinput' else None
        if what: yield (item if proc in INPUT_TOOLS else warn)(f'{proc} {what}',
                                                                fix=f'If you do not know it, find it with: pgrep -a {proc}, then quarantine its program file. Keyloggers work this way.')


RISKY_TALK = {'org.freedesktop.Flatpak': 'can run commands outside its sandbox',
              'org.freedesktop.systemd1': 'can control system services',
              'org.freedesktop.impl.portal.PermissionStore': 'can change other apps\' permissions'}


def flatpak_rows(app, perms):
    c = configparser.ConfigParser(interpolation=None, strict=False); c.optionxform = str
    try: c.read_string(perms)
    except configparser.Error: return
    ctx = c['Context'] if c.has_section('Context') else {}
    for fs in filter(None, ctx.get('filesystems', '').split(';')):
        name, ro = fs.split(':')[0], fs.endswith(':ro')
        if name in ('host', 'host-os', 'host-etc') and not ro:
            yield warn(f'Flatpak {app} can change files outside its sandbox ({fs})', fix=f'Run: flatpak override --user --nofilesystem={name} {app} (or use Flatseal)')
        elif name in ('host', 'home', '~', 'host-os', 'host-etc') or name.startswith(('~/.ssh', '~/.gnupg', '~/.config', 'xdg-config')):
            yield item(f'Flatpak {app}: files {fs}')
    if 'all' in ctx.get('devices', '').split(';'): yield item(f'Flatpak {app}: all devices (camera, USB, input)')
    socks = ctx.get('sockets', '').split(';')
    if 'x11' in socks and 'wayland' not in socks: yield item(f'Flatpak {app}: X11 only (can read other X11 apps\' keystrokes)')
    for sec in ('Session Bus Policy', 'System Bus Policy'):
        for name, mode in (c[sec].items() if c.has_section(sec) else []):
            if name in RISKY_TALK and mode in ('talk', 'own'):
                yield warn(f'Flatpak {app} {RISKY_TALK[name]} ({name})', fix=f'Run: flatpak override --user --no-talk-name={name} {app}')


PORTAL = {('devices', 'camera'): 'may use the camera', ('location', 'location'): 'may see your location',
          ('screenshot', 'screenshot'): 'may take screenshots without asking',
          ('kde-authorized', 'remote-desktop'): 'may control your mouse and keyboard (remote desktop) without asking',
          ('kde-authorized', 'screencast'): 'may record the screen without asking'}


def portal_rows(out):
    """Grants remembered by the desktop portals (`flatpak permissions`: table, object, app, permissions, data)."""
    for l in out.splitlines():
        f = l.split('\t')
        if len(f) < 4 or (f[0], f[1]) not in PORTAL or not re.match(r'(yes|EXACT|NEIGHBORHOOD|CITY|COUNTRY)\b', f[3]): continue
        who = f[2] or 'Unsandboxed apps (no app ID)'
        if f[1] in ('remote-desktop', 'screencast'):
            yield warn(f'{who} {PORTAL[f[0], f[1]]}', fix=f'Unless a tool you use needs it: flatpak permission-remove {f[0]} {f[1]} {f[2]}'.rstrip())
        else: yield item(f'{who} {PORTAL[f[0], f[1]]}', fix=f'Revoke in System Settings > Application Permissions, or: flatpak permission-remove {f[0]} {f[1]} {f[2]}')


@check('App permissions', 'Privacy')
def flatpak_perms():
    """Flatpak sandbox holes (whole-disk access, all devices, X11-only, sandbox-escape D-Bus names), your overrides, and
    camera, location, screenshot and remote-control grants remembered by the desktop portals."""
    if not have('flatpak'): return
    yield from portal_rows(sh('flatpak', 'permissions', timeout=10))
    for app in sh('flatpak', 'list', '--app', '--columns=application').split():
        yield from flatpak_rows(app, sh('flatpak', 'info', '--show-permissions', app, timeout=15))
    for f in files('~/.local/share/flatpak/overrides/*', '/var/lib/flatpak/overrides/*'):
        for l in text(f).splitlines():
            if '=' in l: yield item(f'Flatpak override {os.path.basename(f)}: {l.strip()}')


def usb_devices(root='/sys/bus/usb/devices'):
    """(vid:pid, maker, product, interface classes) for each USB device except root hubs."""
    for d in files(f'{root}/*'):
        vid = text(f'{d}/idVendor').strip()
        if not vid or vid == '1d6b': continue
        ifaces = {(text(f'{i}/bInterfaceClass').strip(), text(f'{i}/bInterfaceProtocol').strip()) for i in files(f'{d}/*:*')}
        yield f'{vid}:{text(f"{d}/idProduct").strip()}', text(f'{d}/manufacturer').strip(), text(f'{d}/product').strip(), ifaces


@check('USB and Thunderbolt devices', 'Devices')
def usb():
    """Every attached USB device, so a new one shows up; a device that is both storage and a keyboard is a BadUSB pattern."""
    for ident, maker, product, ifaces in usb_devices():
        kb, storage = ('03', '01') in ifaces, any(c == '08' for c, _ in ifaces)
        if not ifaces and not product: continue
        label = f'{maker} {product}'.strip() or 'Unnamed device'
        if kb and storage: yield warn(f'USB {label} [{ident}] is both a storage device and a keyboard',
                                      fix='Keystroke-injection gadgets look like this. Unplug it unless you know why it types.')
        if ifaces and all(c == '09' for c, _ in ifaces): continue   # hubs
        yield item(f'USB {label} [{ident}]' + (' (keyboard)' if kb else ''))
    if have('boltctl'):
        for name, status in re.findall(r'^\s*[●○]?\s*(.+?)\n(?:.*\n)*?\s*├─ status:\s*(\S+)', sh('boltctl', 'list', timeout=10), re.M):
            yield item(f'Thunderbolt {name.strip()} ({status})')


@check('Paired devices', 'Devices')
def paired():
    """Bluetooth devices and KDE Connect phones paired with this PC (KDE Connect can run commands and read notifications)."""
    if sh('systemctl', 'is-active', 'bluetooth').strip() == 'active' and have('bluetoothctl'):
        for mac, name in re.findall(r'^Device (\S+) (.+)$', sh('bluetoothctl', 'devices', 'Paired', timeout=5), re.M):
            yield item(f'Bluetooth {name} [{mac}]')
    c = configparser.ConfigParser(interpolation=None, strict=False)
    try: c.read_string(text(f'{HOME}/.config/kdeconnect/trusted_devices'))
    except configparser.Error: pass
    for dev in c.sections(): yield item(f'KDE Connect trusts {c[dev].get("name", dev)}', fix='Review in System Settings > KDE Connect; unpair phones you no longer use.')


def wifi_row(ssid, km, proto, auto, uuid):
    """One saved Wi-Fi network: open or WEP/WPA1 networks that join by themselves are easy to fake or sniff."""
    weak = 'open (no encryption)' if not km else 'WEP' if km in ('none', 'ieee8021x') else 'WPA1' if km == 'wpa-psk' and proto == 'wpa' else None
    if not weak: return None
    fix = f'Anyone nearby can read the traffic or fake "{ssid}". Stop auto-joining it: nmcli connection modify uuid {uuid} connection.autoconnect no'
    return warn(f'Saved Wi-Fi "{ssid}" is {weak} and joins automatically', fix=fix) if auto == 'yes' else item(f'Saved Wi-Fi "{ssid}" is {weak}')


@check('Wi-Fi networks', 'Network')
def wifi():
    if not have('nmcli'): return
    for l in sh('nmcli', '-t', '-f', 'UUID,TYPE', 'connection', 'show', timeout=10).splitlines():
        uuid, _, kind = l.partition(':')
        if kind != '802-11-wireless': continue
        f = sh('nmcli', '-t', '-g', '802-11-wireless.ssid,802-11-wireless-security.key-mgmt,802-11-wireless-security.proto,connection.autoconnect',
               'connection', 'show', 'uuid', uuid, timeout=10).split('\n')
        if len(f) >= 4 and (r := wifi_row(*f[:4], uuid)): yield r


HISTORY = ('~/.bash_history', '~/.zsh_history', '~/.zhistory', '~/.local/share/fish/fish_history', '~/.python_history',
           '~/.mysql_history', '~/.psql_history', '~/.sqlite_history', '~/.node_repl_history', '~/.rediscli_history')
NOT_A_VALUE = r'(?![$<]|CHANGEME|\*+\s)'   # $VAR, <placeholder>, CHANGEME and masked values are not secrets
HIST_SECRETS = [(k, re.compile(p)) for k, p in (
    ('password on a command line', r'(?:\bsshpass\s+-p\s*|\bmysql\w*\b.*?\s-p(?=\S)|--pass(?:word)?[= ]\s*|\bPGPASSWORD=|'
                                   r'\becho\s+(?=\S+\s*\|\s*sudo\s+-S))["\']?' + NOT_A_VALUE + r'[^\s"\']{4,}'),
    ('password in a URL', r'\w+://[^/\s:@]+:' + NOT_A_VALUE + r'[^@\s/]{3,}@'),
    ('curl password', r'\bcurl\b.*?(?:\s-u\s*|--user[= ])[^\s:]+:' + NOT_A_VALUE + r'\S{3,}'),
    ('secret in a variable', r'\b\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)\w*=["\']?' + NOT_A_VALUE + r'[^\s"\'$]{8,}'),
    ('AWS key', r'\bAKIA[0-9A-Z]{16}\b'))]


def history_secrets(t):
    """(lines with a secret, kinds of secret) in a history file's text; the values themselves are never kept."""
    n, kinds = 0, set()
    for l in t.splitlines():
        k = {name for name, rx in HIST_SECRETS if rx.search(l)} | set(secret_kinds(l))
        if k: n, kinds = n + 1, kinds | k
    return n, sorted(kinds)


@check('Secrets in shell history', 'Privacy')
def history():
    """Passwords, tokens and keys typed into a shell or REPL stay in its history file, which infostealers collect first."""
    for f in files(*HISTORY):
        n, kinds = history_secrets(text(f))
        if n: yield warn(f'{f.replace(HOME, "~")} holds {n} commands with secrets ({", ".join(kinds)})',
                         fix='Delete those lines from the file and change the secrets. Start a command with a space to keep it out of '
                             'history (bash: HISTCONTROL=ignorespace), or pass secrets through a file or prompt instead.')


SENSITIVE_EXT = {'.txt', '.csv', '.md', '.json', '.rtf', '.text', '.note', '.pem', '.key', ''}
CARD = re.compile(r'(?<![\d.-])(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?![\d.-])')
CARD_WORDS = re.compile(r'\b(card|visa|mastercard|amex|cvv|cvc|expir)', re.I)
NOT_BIP39 = {'the', 'and', 'for', 'that', 'this', 'with', 'you', 'are', 'was', 'not', 'but', 'have', 'from', 'they', 'will', 'there',
             'their', 'what', 'when', 'which', 'your', 'can', 'has', 'had', 'were', 'been', 'its', 'our', 'him', 'her', 'his', 'she'}
WALLET_WORDS = re.compile(r'seed|recovery|mnemonic|phrase|wallet|metamask|ledger|trezor|exodus|phantom|bip39', re.I)


def luhn(d):
    total = sum(int(c) if i % 2 == 0 else (int(c) * 2 - 9 if int(c) > 4 else int(c) * 2) for i, c in enumerate(reversed(d)))
    return total % 10 == 0


def sensitive(name, t):
    """Kinds of sensitive data in one plain-text file (nothing of the data itself)."""
    kinds, head = [], t[:2000].lower()
    cols = set(re.findall(r'[a-z_]+', head.split('\n', 1)[0]))   # a CSV export's header line
    if {'url', 'password'} <= cols and cols & {'username', 'login', 'login_username'} or \
       ('"encrypted": false' in head and '"login"' in t[:200000]):
        kinds.append('a password-manager export')
    if '-----BEGIN' in t and re.search(r'-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', t):
        kinds.append('a private key' + (' (passphrase-protected)' if 'ENCRYPTED' in t or 'Proc-Type: 4,ENCRYPTED' in t else ''))
    if CARD_WORDS.search(t) and any(luhn(re.sub(r'\D', '', m)) for m in CARD.findall(t)): kinds.append('card numbers')
    if (WALLET_WORDS.search(name) or WALLET_WORDS.search(t[:20000])) and recovery_phrase(t): kinds.append('a wallet recovery phrase')
    return kinds


def recovery_phrase(t):
    """A run of exactly 12-24 (in steps of 3) short lowercase words, none of them common English, at most one repeated;
    numbering like '1.' between the words is allowed. Linear in the text."""
    run = []
    for tok in re.findall(r'[^\s,]+', t) + ['.']:
        if re.fullmatch(r'\d{1,2}[.):]?', tok): continue
        if re.fullmatch(r'[a-z]{3,8}', tok) and tok not in NOT_BIP39: run.append(tok); continue
        if len(run) in (12, 15, 18, 21, 24) and len(set(run)) >= len(run) - 1: return True
        run = []
    return False


@check('Sensitive files', 'Privacy')
def sensitive_files():
    """Password exports, private keys, card numbers and wallet recovery phrases saved as plain text where infostealers look."""
    for p, st in walk([f'{HOME}/{d}' for d in ('Desktop', 'Documents', 'Downloads')], 3):
        if st.st_size > (1 << 20) or os.path.splitext(p)[1].lower() not in SENSITIVE_EXT: continue
        if kinds := sensitive(os.path.basename(p), text(p)):
            yield warn(f'{p.replace(HOME, "~")} holds {" and ".join(kinds)} in plain text',
                       fix='Infostealers copy files like this first. Move it into your password manager or an encrypted vault '
                           '(KeePassXC, Cryptomator), then delete it and empty the Trash. Encrypted keys are lower risk.')
