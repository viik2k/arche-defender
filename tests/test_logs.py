import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import unittest
from datetime import datetime, timezone
from unittest import mock
from arche import logs, intel
from arche.core import ALERT, WARN, INFO


def run(events):
    with mock.patch.object(intel, 'ip_hit', return_value=None):
        return list(logs.analyse(events))


class Analyse(unittest.TestCase):
    def test_burst(self):
        self.assertEqual(logs.burst([0, 100, 5000, 5100, 5200, 5300]), (4, 5000))
        self.assertEqual(logs.burst([]), (0, None))

    def test_password_guessing(self):
        ev = [(1000 + i * 30, 'kscreenlocker_greet', 'pam_unix(kde:auth): authentication failure; user=finn') for i in range(5)]
        r = run(ev)
        self.assertEqual(len(r), 1); self.assertEqual(r[0][1], WARN); self.assertIn('screen unlock', r[0][0])
        self.assertEqual(run(ev[:4]), [])                                       # a few typos are not an attack
        self.assertEqual(run([(i * 3600, 'sudo', ev[0][2]) for i in range(6)]), [])  # spread over hours

    def test_ssh_brute_then_login(self):
        ev = [(i, 'sshd-session', f'Invalid user admin{i} from 203.0.113.9 port 4{i}') for i in range(3)]
        ev += [(9, 'sshd-session', f'Failed password for invalid user admin{i} from 203.0.113.9 port 4{i} ssh2') for i in range(3)]
        ev += [(10, 'sshd', 'Failed password for root from 203.0.113.9 port 5 ssh2')] * 2
        ev += [(20, 'sshd', 'Accepted password for root from 203.0.113.9 port 6 ssh2'),
               (21, 'sshd', 'Accepted publickey for finn from 192.168.4.20 port 7 ssh2: ED25519 SHA256:x')]
        r = {t: s for t, s, _ in run(ev)}
        self.assertEqual(r['5 failed SSH logins from 203.0.113.9'], WARN)       # invalid-user lines counted once
        self.assertEqual(r['SSH login as root from 203.0.113.9 succeeded after 5 failures'], ALERT)
        self.assertEqual(r['SSH login as finn from 192.168.4.20 (publickey)'], INFO)
        with mock.patch.object(intel, 'ip_hit', lambda ip: 'feodo' if ip == '198.51.100.4' else None):
            self.assertEqual([(t, s) for t, s, _ in logs.analyse([(1, 'sshd', 'Accepted publickey for finn from 198.51.100.4 port 2 ssh2')])],
                             [('SSH login as finn from 198.51.100.4, an address on threat list feodo', ALERT)])

    def test_tamper(self):
        sudo = lambda c: (0, 'sudo', f'finn : TTY=pts/1 ; PWD=/home/finn ; USER=root ; COMMAND={c}')
        bad = ['/usr/sbin/setenforce 0', '/usr/bin/systemctl disable --now firewalld', '/usr/sbin/ufw disable', '/usr/sbin/visudo',
               '/usr/bin/tee /etc/sudoers.d/nopw', '/usr/sbin/nft flush ruleset', '/usr/sbin/sysctl -w kernel.yama.ptrace_scope=0',
               '/usr/bin/rm -rf /var/log/secure', '/usr/sbin/grubby --update-kernel=ALL --args=mitigations=off']
        ok = ['/usr/sbin/dnf install x', '/usr/sbin/systemctl restart firewalld', '/usr/sbin/systemctl enable sshd', '/usr/sbin/setenforce 1',
              '/usr/sbin/sysctl -w kernel.yama.ptrace_scope=1', '/usr/bin/chmod 755 /usr/local/bin/x']
        for c in bad: self.assertEqual([s for _, s, _ in run([sudo(c)])], [WARN], c)
        for c in ok: self.assertEqual(run([sudo(c)]), [], c)
        r = run([(0, 'pkexec', 'finn: Executing command [USER=root] [TTY=unknown] [CWD=/home/finn] [COMMAND=/usr/sbin/setenforce 0]')])
        self.assertTrue(r[0][0].startswith('Put SELinux in permissive mode with pkexec'))

    def test_accounts(self):
        ev = [(0, 'useradd', 'new user: name=eve, UID=1001, GID=1001, home=/home/eve'),
              (0, 'useradd', 'new user: name=ollama, UID=971, GID=969'),
              (0, 'usermod', "add 'eve' to group 'wheel'"), (0, 'usermod', "add 'eve' to shadow group 'wheel'"),
              (0, 'usermod', "add 'ollama' to group 'video'"), (0, 'gpasswd', 'user bob added by root to group docker'),
              (0, 'sudo', 'eve : user NOT in sudoers ; TTY=pts/1 ; COMMAND=/bin/sh')]
        r = run(ev)
        sev = {t.split(' on ')[0].split(' (')[0]: s for t, s, _ in r}
        self.assertEqual(sev['New login account eve was created'], WARN)
        self.assertEqual(sev['New system account ollama'], INFO)
        self.assertEqual(sev['eve was added to the wheel group'], WARN)
        self.assertEqual(sev['bob was added to the docker group'], WARN)
        self.assertEqual(sev['An account without admin rights tried sudo'], ALERT)
        self.assertEqual(len(r), 5)



class Installed(unittest.TestCase):
    def test_history(self):
        import json, time
        now = time.time()
        tx = json.dumps([{'command_line': 'dnf install -y evil', 'start_time': now - 60, 'altered_count': 1},
                         {'command_line': 'dnf upgrade --refresh', 'start_time': now - 60, 'altered_count': 90},
                         {'command_line': '', 'start_time': now - 120, 'altered_count': 2},
                         {'command_line': 'dnf install old', 'start_time': now - 30 * 86400, 'altered_count': 1}])
        fp = 'deploy install\tapp/com.example.App/x86_64/stable\tflathub\tuser\ndeploy install\truntime/org.kde.Platform/x86_64/6.9\tflathub\tuser\n' \
             'deploy update\tapp/org.x.Y/x86_64/stable\tflathub\tsystem\nuninstall\tapp/org.gone.App/x86_64/stable\t\tsystem\n'
        with mock.patch.object(logs, 'sh', side_effect=lambda *a, **k: tx if a[0] == 'dnf' else fp):
            r = [t.split(' (')[0] for t, _, _ in logs.installed()]
        self.assertEqual(r, ['dnf: dnf install -y evil', 'dnf: Discover or PackageKit',
                             'Flatpak installed com.example.App from flathub', 'Flatpak removed org.gone.App from ?'])


if __name__ == '__main__':
    unittest.main()


class Snaps(unittest.TestCase):
    def test_changes(self):
        out = """ID   Status  Spawn                 Ready                 Summary
1    Done    2026-10-01T09:00:00Z  2026-10-01T09:01:00Z  Initialize system state
7    Done    2026-10-02T09:00:00Z  2026-10-02T09:01:00Z  Install "old" snap
9    Done    2026-11-15T10:00:00Z  2026-11-15T10:01:00Z  Install "vlc" snap
10   Done    2026-11-15T11:00:00Z  2026-11-15T11:01:00Z  Install "tool" snap from file "/home/u/tool.snap"
11   Doing   2026-11-16T08:00:00Z  -                     Remove "vlc" snap
12   Done    2026-11-16T09:00:00Z  2026-11-16T09:01:00Z  Refresh "core22" snap
"""
        cut = datetime(2026, 11, 10, tzinfo=timezone.utc).timestamp()
        self.assertEqual([t for t, _, _ in logs.snap_changes(out, cut)],
                         ['Snap installed vlc', 'Snap installed tool from a file, without a store signature', 'Snap removed vlc'])


class BriefKeyboards(unittest.TestCase):
    def test_brief(self):
        ev = [(100, 'b1', 'usb 1-4: New USB device found, idVendor=03eb, idProduct=2401, bcdDevice= 1.00'),
              (100.1, 'b1', 'usb 1-4: Product: Keyboard'),
              (100.3, 'b1', 'hid-generic 0003:03EB:2401.0007: input,hidraw6: USB HID v1.11 Keyboard [Keyboard] on usb-0000:00:14.0-4/input0'),
              (110, 'b1', 'usb 5-2.1: New USB device found, idVendor=346e, idProduct=0005, bcdDevice= 1.00'),   # a racing wheel: not a keyboard
              (130, 'b1', 'usb 5-2.1: USB disconnect, device number 6'),
              (140, 'b1', 'usb 1-4: USB disconnect, device number 9'),
              (200, 'b1', 'usb 1-5: New USB device found, idVendor=046d, idProduct=c339, bcdDevice=13.02'),
              (200.2, 'b1', 'logitech 0003:046D:C339.0008: input,hidraw7: USB HID v1.11 Keyboard [Logitech Pro] on usb-0000:00:14.0-5/input0'),
              (900, 'b1', 'usb 1-5: USB disconnect, device number 10'),   # plugged in for 700 s
              (1000, 'b2', 'usb 1-6: New USB device found, idVendor=046d, idProduct=c339, bcdDevice=13.02'),
              (1000.2, 'b2', 'hid-generic 0003:046D:C339.0001: input,hidraw1: USB HID v1.11 Keyboard [Logitech Pro] on usb-0000:00:14.0-6/input0'),
              (1010, 'b2', 'usb 1-6: USB disconnect, device number 2')]
        self.assertEqual(list(logs.brief_keyboards(ev)), [('03eb:2401', 'Keyboard', 40, 100), ('046d:c339', '', 10, 1000)])
        self.assertEqual(list(logs.brief_keyboards(ev, {'046d:c339'})), [('03eb:2401', 'Keyboard', 40, 100)])   # attached now: yours
