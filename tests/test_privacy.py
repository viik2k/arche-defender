import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import base64, shutil, tempfile, unittest
from unittest import mock
from pathlib import Path
from arche import privacy
from arche.core import WARN, INFO

PERMS = """[Context]
shared=network;ipc;
sockets=x11;pulseaudio;
devices=all;
filesystems=host;xdg-download;~/.ssh:ro;

[Session Bus Policy]
org.freedesktop.Flatpak=talk
org.kde.StatusNotifierWatcher=talk
"""


class Flatpak(unittest.TestCase):
    def test_rows(self):
        r = {t: s for t, s, _ in privacy.flatpak_rows('com.example.App', PERMS)}
        self.assertEqual(r['Flatpak com.example.App can change files outside its sandbox (host)'], WARN)
        self.assertEqual(r['Flatpak com.example.App: files ~/.ssh:ro'], INFO)
        self.assertIn('Flatpak com.example.App: all devices (camera, USB, input)', r)
        self.assertIn("Flatpak com.example.App: X11 only (can read other X11 apps' keystrokes)", r)
        self.assertEqual(r['Flatpak com.example.App can run commands outside its sandbox (org.freedesktop.Flatpak)'], WARN)
        self.assertEqual(len(r), 5)                                                  # xdg-download and StatusNotifier are fine

    def test_read_only_host_and_garbage(self):
        self.assertEqual([s for _, s, _ in privacy.flatpak_rows('a', '[Context]\nfilesystems=host:ro;\nsockets=wayland;x11;\n')], [INFO])
        self.assertEqual(list(privacy.flatpak_rows('a', 'not ini')), [])


class Snap(unittest.TestCase):
    def test_connections(self):
        out = '''Interface                 Plug                        Slot                       Notes
audio-playback            firefox:audio-playback      :audio-playback            -
camera                    firefox:camera              :camera                    -
personal-files            code:dot-vscode             :personal-files            -
ssh-keys                  sshtool:ssh-keys            :ssh-keys                  manual
content[gtk-3-themes]     firefox:gtk-3-themes        gtk-common-themes:gtk-3-themes  -
'''
        self.assertEqual([(s, t, f) for t, s, f in privacy.snap_rows(out)], [
            (INFO, 'Snap firefox may use the camera', 'If it does not need it: sudo snap disconnect firefox:camera'),
            (INFO, 'Snap code may read files outside its sandbox (dot-vscode)', 'If it does not need it: sudo snap disconnect code:dot-vscode'),
            (WARN, 'Snap sshtool may read your SSH private keys', 'If it does not need it: sudo snap disconnect sshtool:ssh-keys')])


class Wifi(unittest.TestCase):
    def test_rows(self):
        self.assertEqual(privacy.wifi_row('Cafe', '', '', 'yes', 'u1')[1], WARN)
        self.assertEqual(privacy.wifi_row('Cafe', '', '', 'no', 'u1'), ('Saved Wi-Fi "Cafe" is open (no encryption)', INFO, None))
        self.assertIn('WEP', privacy.wifi_row('Old', 'none', '', 'yes', 'u2')[0])
        self.assertIn('WPA1', privacy.wifi_row('Old', 'wpa-psk', 'wpa', 'yes', 'u3')[0])
        for km, proto in (('wpa-psk', ''), ('wpa-psk', 'rsn'), ('sae', ''), ('owe', ''), ('wpa-eap', '')):
            self.assertIsNone(privacy.wifi_row('Home', km, proto, 'yes', 'u4'), km)


class Usb(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.d, True)

    def dev(self, name, vid, product, ifaces):
        d = self.d / name; d.mkdir()
        for f, v in (('idVendor', vid), ('idProduct', '0001'), ('product', product), ('manufacturer', 'Acme')):
            (d / f).write_text(v + '\n')
        for i, (cls, proto) in enumerate(ifaces):
            (d / f'{name}:1.{i}').mkdir(); (d / f'{name}:1.{i}' / 'bInterfaceClass').write_text(cls); (d / f'{name}:1.{i}' / 'bInterfaceProtocol').write_text(proto)

    def test_devices(self):
        self.dev('usb1', '1d6b', 'xHCI Host Controller', [('09', '00')])
        self.dev('1-1', '05ac', 'Stick', [('08', '50'), ('03', '01')])
        devs = list(privacy.usb_devices(self.d))
        self.assertEqual(len(devs), 1)                                               # root hub skipped
        ident, maker, product, ifaces = devs[0]
        self.assertEqual((ident, maker, product), ('05ac:0001', 'Acme', 'Stick'))
        self.assertIn(('03', '01'), ifaces); self.assertIn(('08', '50'), ifaces)
        with mock.patch.object(privacy, 'usb_devices', return_value=devs), mock.patch.object(privacy, 'have', return_value=False):
            r = list(privacy.usb())
        self.assertEqual(r[0][1], WARN); self.assertIn('both a storage device and a keyboard', r[0][0])
        self.assertEqual(r[1][0], 'USB Acme Stick [05ac:0001] (keyboard)')


DEVICES = """I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
H: Handlers=kbd event0
B: EV=3

I: Bus=0003 Vendor=046d Product=c339 Version=0111
N: Name="Logitech Pro Gaming Keyboard"
H: Handlers=sysrq kbd leds event7
B: EV=120013

N: Name="Turtle Beach Recon Controller"
H: Handlers=event9 js0
B: EV=1b
"""


class Input(unittest.TestCase):
    def test_keyboard_readers(self):
        kb = privacy.keyboards(DEVICES)
        self.assertEqual(kb, {'event7': 'Logitech Pro Gaming Keyboard'})
        opened = [('kwin_wayland', '/dev/input/event7'), ('steam', '/dev/input/event9'), ('steam', '/dev/uinput'),
                  ('espanso', '/dev/input/event7'), ('updater', '/dev/input/event7'), ('updater', '/dev/input/event0')]
        rows = [(s, t) for t, s, _ in privacy.input_rows(opened, kb, False)]
        self.assertEqual(rows, [(INFO, 'espanso reads your keyboard (Logitech Pro Gaming Keyboard)'), (INFO, 'steam can type and click as you (/dev/uinput)'),
                                (WARN, 'updater reads your keyboard (Logitech Pro Gaming Keyboard)')])
        self.assertEqual([s for _, s, _ in privacy.input_rows([], kb, True)], [WARN])


class Clipboard(unittest.TestCase):
    def test_kinds(self):
        fake = 'ghp_' + 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4'
        self.assertEqual(privacy.clip_kinds(['hello world', None, 'Tr0ub4dor&3xQ']), ['a password'])
        self.assertEqual(privacy.clip_kinds(['def f(x): return x', 'snake_case_Name1', 'https://youtu.be/watch?v=dQw4w9WgXcQ',
                                             '~/Desktop/Repos/arche2.py', 'Jane.Doe1@Example.com', 'self.assertEqual(x1)']), [])
        self.assertIn('GitHub token', privacy.clip_kinds([fake]))

    def test_gnome_registry(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        p = Path(d, 'registry.txt'); p.write_text('[{"contents": "a", "favorite": false}, "b"]')
        self.assertEqual(privacy.clip_entries(str(p)), ['a', 'b'])


class Crashes(unittest.TestCase):
    def test_rows(self):
        env = 'HOME=/home/u\nSSH_AUTH_SOCK=/run/user/1000/ssh-agent\nGITHUB_TOKEN=ghp_' + 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF2hJ5' + \
              '\nDB_PASSWORD=$PGPASS\nSTARSHIP_SESSION_KEY=4815162342\nOPENAI_API_KEY=sk-proj-' + 'Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe' + '\n'
        entries = [{'COREDUMP_UID': '1000', 'COREDUMP_EXE': '/usr/bin/python3', 'COREDUMP_ENVIRON': list(env.encode())},
                   {'COREDUMP_UID': '1000', 'COREDUMP_EXE': '/usr/lib/brave/brave', 'COREDUMP_FILENAME': '/var/lib/systemd/coredump/core.brave.1000.x.42.1.zst'},
                   {'COREDUMP_UID': '1000', 'COREDUMP_EXE': '/usr/bin/kate', 'COREDUMP_FILENAME': '/var/lib/systemd/coredump/core.kate.1000.x.43.1.zst'},
                   {'COREDUMP_UID': '0', 'COREDUMP_EXE': '/usr/bin/sudo', 'COREDUMP_ENVIRON': 'API_TOKEN=abcdefgh12345678'}]
        r = [(t, s, f) for t, s, f in privacy.crash_rows(entries, 1000, exists=lambda f: True)]
        self.assertEqual([t for t, _, _ in r], [
            'The system journal kept the environment of a crashed python3, with 2 secrets: GITHUB_TOKEN, OPENAI_API_KEY',
            'A memory dump of brave from a crash is on disk, where programs running as you can read it (it can hold passwords and sign-in cookies)'])
        self.assertEqual(r[1][2], 'Delete it: sudo rm /var/lib/systemd/coredump/core.brave.1000.x.42.1.zst')
        self.assertTrue(all(s == WARN for _, s, _ in r))
        self.assertEqual(list(privacy.crash_rows(entries[1:2], 1000, exists=lambda f: False)), [])   # cleaned up already


if __name__ == '__main__':
    unittest.main()


class History(unittest.TestCase):
    def test_secrets(self):
        bad = ['sshpass -p hunter22 ssh pi@nas', 'mysql -u root -pS3cretPass db', 'curl -u admin:letmein123 http://x',
               'git clone https://bob:ghp_R8kq2LmZ7vTnW4xYp9sJ3hB6cD1fG5aE0uQi@github.com/x/y', 'export DB_PASSWORD="correcthorse"',
               ': 1700000000:0;docker login --password Tr0ub4dor reg', 'echo hunter22 | sudo -S dnf install x', 'AKIAABCDEFGHIJKLMNOP']
        ok = ['mysql -u root -p mydb', 'docker login --password-stdin', 'export API_KEY=$(secret-tool lookup x y)',
              'export TOKEN=CHANGEME', 'docker run -u 1000:1000 img', 'curl -u "$USER:$PASS" x', 'git push', 'export TOKEN=<your-token>']
        for l in bad: self.assertEqual(privacy.history_secrets(l)[0], 1, l)
        for l in ok: self.assertEqual(privacy.history_secrets(l)[0], 0, l)
        n, kinds = privacy.history_secrets('\n'.join(bad))
        self.assertEqual(n, len(bad)); self.assertIn('GitHub token', kinds)


class Portal(unittest.TestCase):
    def test_rows(self):
        out = ('notifications\tnotification\tio.x.A\tyes\t0x00\nkde-authorized\tremote-desktop\t\tyes\t0x00\n'
               'devices\tcamera\torg.telegram.desktop\tyes\t0x00\ndevices\tcamera\tcom.x.B\tno\t0x00\n'
               'location\tlocation\torg.gnome.Maps\tEXACT,1700000000\t0x00\n')
        rows = list(privacy.portal_rows(out))
        self.assertEqual([(s, t) for t, s, _ in rows],
                         [(WARN, 'Unsandboxed apps (no app ID) may control your mouse and keyboard (remote desktop) without asking'),
                          (INFO, 'org.telegram.desktop may use the camera'), (INFO, 'org.gnome.Maps may see your location')])
        self.assertTrue(rows[0][2].endswith('permission-remove kde-authorized remote-desktop'))


class Sensitive(unittest.TestCase):
    PHRASE = 'abandon ability able about above absent absorb abstract absurd abuse access accident'

    def test_kinds(self):
        S = privacy.sensitive
        self.assertEqual(S('pw.csv', 'name,url,username,password,note\nx,https://a,b,c,\n'), ['a password-manager export'])
        self.assertEqual(S('k', '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n'), ['a private key'])
        self.assertEqual(S('c.txt', 'Visa 4111 1111 1111 1111 exp 12/29'), ['card numbers'])
        self.assertEqual(S('c.txt', 'card 4111 1111 1111 1112'), [])                    # fails Luhn
        self.assertEqual(S('p.json', '{"x": 4111111111111111.5}'), [])                  # no card words, decimal
        self.assertEqual(S('seed.txt', self.PHRASE), ['a wallet recovery phrase'])
        self.assertEqual(S('seed.txt', '\n'.join(f'{i}. {w}' for i, w in enumerate(self.PHRASE.split(), 1))), ['a wallet recovery phrase'])
        self.assertEqual(S('notes.txt', self.PHRASE), [])                               # no wallet context
        self.assertEqual(S('seed.txt', self.PHRASE + ' extra'), [])                     # 13 words
        self.assertEqual(S('seed.txt', 'the ' + self.PHRASE[8:]), [])                   # common English

    def test_key_locked(self):
        key = lambda cipher: '-----BEGIN OPENSSH PRIVATE KEY-----\n' + base64.b64encode(
            b'openssh-key-v1\0' + len(cipher).to_bytes(4, 'big') + cipher + bytes(48)).decode() + '\n'
        self.assertEqual(privacy.sensitive('k', key(b'none')), ['a private key'])
        self.assertEqual(privacy.sensitive('k', key(b'aes256-ctr')), ['a private key (passphrase-protected)'])

    def test_folders(self):
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d)
        ssh = d / 'migration/dotfiles/.ssh'; ssh.mkdir(parents=True)   # a copy of ~/.ssh left behind
        for n in ('id_rsa', 'id_ed25519'): (ssh / n).write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n')
        (ssh / 'id_rsa.pub').write_text('ssh-rsa AAAA')
        (d / 'migration/dotfiles/auth.json').write_text('{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjoxOTk5OTk5OTk5fQ.Qm9vdGgtdGhpcy1pcy1hLXRlc3Qtc2lnbmF0dXJl"}')
        (d / 'Documents').mkdir(); (d / 'Documents/seed.txt').write_text(self.PHRASE)
        (d / '.config').mkdir(); (d / '.config/k').write_text('-----BEGIN OPENSSH PRIVATE KEY-----\n')   # the apps' own folders
        with mock.patch.object(privacy, 'HOME', str(d)):
            r = sorted(t for t, _, _ in privacy.sensitive_files())
        self.assertEqual(r, ['~/Documents/seed.txt holds a wallet recovery phrase in plain text',
                             '~/migration/dotfiles/.ssh holds 2 plain-text files with secrets: private key',
                             '~/migration/dotfiles/auth.json holds keys or tokens (JWT) in plain text'])

    def test_linear(self):
        import time
        t, s = '\t \n' * 300000 + 'url', time.time()
        privacy.sensitive('driveline', t)
        self.assertLess(time.time() - s, 1)
