import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import unittest
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
