# Privacy and devices: what can see or hear you right now, what sandboxed apps are allowed to touch,
# and the hardware that is plugged in or paired (a new "keyboard" can be a BadUSB).
import configparser, json, os, re
from .core import check, alert, warn, item, sh, have, text, files, HOME
from .ai import secret_kinds


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
    """Apps that have the camera, a microphone or a screen capture open at the moment of the scan."""
    for fd in files('/proc/[0-9]*/fd/*'):
        try:
            if re.match(r'/dev/video\d+$', os.readlink(fd)): yield item(f'Camera open by {comm(fd.split("/")[2])}')
        except OSError: pass   # ponytail: other users' processes need root
    for mc, app, node in pipewire_streams():
        if mc.endswith('/Internal'): continue
        if mc.startswith('Stream/Input/Audio'): yield item(f'Microphone open by {app}')
        elif mc.startswith('Stream/Input/Video'): yield item(f'Camera or screen capture open by {app}')
        elif 'portal' in node.lower() or 'screen' in node.lower(): yield item(f'Screen is being shared ({app})')


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


@check('App permissions', 'Privacy')
def flatpak_perms():
    """Flatpak sandbox holes: whole-disk access, all devices, X11-only apps and sandbox-escape D-Bus names; plus your overrides."""
    if not have('flatpak'): return
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
