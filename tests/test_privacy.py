import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import shutil, tempfile, unittest
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


if __name__ == '__main__':
    unittest.main()
