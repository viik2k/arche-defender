import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import shutil, tempfile, unittest
from pathlib import Path
from unittest import mock
from arche import updates
from arche.core import INFO, WARN


class Kernels(unittest.TestCase):
    def test_flavour(self):
        inst = ['7.3.4-201.nobara.fc44.x86_64', '7.3.10-200.nobara.fc44.x86_64', '7.4.1-201.eac.nobara.fc44.x86_64']
        self.assertEqual(updates.newest_same_flavor(inst[0], inst), inst[1])        # 10 > 4, natural order
        self.assertEqual(updates.newest_same_flavor(inst[2], inst), inst[2])        # eac only compares with eac
        self.assertEqual(updates.newest_same_flavor('6.1.0', []), '6.1.0')


class Pending(unittest.TestCase):
    def test_advisories_only_with_updateinfo(self):
        out = {'check-upgrade': 'bash.x86_64  5.3-2.fc44  updates\n', 'advisory': 'FEDORA-2026-1 Critical/Sec. bash-5.3-2.fc44.x86_64\n'}
        sh = mock.Mock(side_effect=lambda *a, **k: out[a[3]])
        for cached, want in (([], ['1 package updates waiting']), (['/var/cache/libdnf5/f/repodata/x-updateinfo.xml.zst'],
                             ['1 security updates waiting, 1 critical', '1 package updates waiting'])):
            with mock.patch.object(updates, 'have', lambda c: c == 'dnf'), mock.patch.object(updates, 'sh', sh), \
                 mock.patch.object(updates, 'files', lambda *g: cached if 'updateinfo' in g[0] else []):
                self.assertEqual([t for t, _, _ in updates.pending()], want)
        self.assertEqual([c.args[3] for c in sh.call_args_list], ['check-upgrade', 'check-upgrade', 'advisory'])


class Snaps(unittest.TestCase):
    def test_rows(self):
        listing = '''Name             Version   Rev    Tracking       Publisher     Notes
core22           20240111  1122   latest/stable  canonical**   base
code             e170252f  174    latest/stable  vscode**      classic
mytool           0.1       x1     -              -             -
tester           1.0       3      latest/edge    someone       devmode
exodus-wallet    24.1      7      latest/stable  cryptoguy     -
notes-app        2.0       12     latest/stable  indie*        held
vlc              3.0       3777   latest/stable  videolan**    -
'''
        rows = [(s, t) for t, s, _ in updates.snap_rows(listing, 'timer: 00:00~24:00/4\nhold: forever\n')]
        self.assertEqual(rows, [
            (WARN, 'Snap updates are paused (forever)'),
            (INFO, 'Snap code is unconfined (classic): it can read and change all your files, like a normal package'),
            (WARN, 'Snap mytool was installed from a file without a store signature (--dangerous)'),
            (WARN, 'Snap tester runs in devmode, without its sandbox'),
            (INFO, 'Snap tester comes from an unverified publisher (someone)'),
            (WARN, 'Snap exodus-wallet looks like a crypto wallet, but its publisher cryptoguy is not verified (fake wallet snaps steal recovery phrases)'),
            (WARN, 'Updates for snap notes-app are paused')])
        self.assertEqual(list(updates.snap_rows('', '')), [])


class Hsi(unittest.TestCase):
    def test_levels(self):
        ok, bad = ['success'], []
        a = [{'HsiLevel': 1, 'Flags': ok}, {'HsiLevel': 1, 'Flags': ok}, {'HsiLevel': 2, 'Flags': bad}, {'HsiLevel': 3, 'Flags': ok}]
        self.assertEqual(updates.hsi(a), 'HSI:1')
        self.assertEqual(updates.hsi(a + [{'Flags': bad}]), 'HSI:1!')               # runtime issue
        self.assertEqual(updates.hsi([{'HsiLevel': 1, 'Flags': bad}]), 'HSI:0')



class Sources(unittest.TestCase):
    def test_dnf_repos(self):
        repos = [{'id': 'fedora', 'is_enabled': True, 'metalink': 'https://mirrors.fedoraproject.org/metalink?repo=x', 'pkg_gpgcheck': True},
                 {'id': 'sketchy', 'is_enabled': True, 'base_url': ['http://repo.example/x'], 'pkg_gpgcheck': False, 'repo_file_path': '/etc/yum.repos.d/s.repo'},
                 {'id': 'plain', 'base_url': ['http://repo.example/y'], 'pkg_gpgcheck': True},
                 {'id': 'off', 'is_enabled': False, 'pkg_gpgcheck': False}]
        r = [(t, s) for t, s, _ in updates.dnf_repo_rows(repos)]
        self.assertEqual(r, [('Package source: fedora (mirrors.fedoraproject.org)', INFO),
                             ('Packages from repo sketchy (repo.example) are installed without a signature check', WARN),
                             ('Repo plain is fetched over plain http (repo.example); its packages are still signature-checked', INFO)])



class Electron(unittest.TestCase):
    def test_apps_and_support(self):
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d)
        app = d / 'flatpak/app/com.example.Chat/current/active/files/chat'; app.mkdir(parents=True); (app / 'icudtl.dat').touch()
        exe = app / 'chat'
        with open(exe, 'wb') as f: f.truncate(21 << 20); f.seek(12 << 20); f.write(b'Mozilla/5.0 Chrome/128.0.6613.36 Electron/32.3.0 Safari/537.36')
        exe.chmod(0o755)
        (d / 'chrome').mkdir(); (d / 'chrome/icudtl.dat').touch()   # a browser, not Electron
        with mock.patch.object(updates, 'RUNTIMES', (f'{d}/chrome', f'{d}/flatpak/app/*/current/active/files/*')):
            apps = list(updates.electron_apps())
        self.assertEqual(apps, [('com.example.Chat', str(app), '32.3.0', 128)])
        rel = [{'version': v} for v in ('47.0.0-nightly.20261113', '46.0.0-beta.3', '45.2.1', '44.10.2', '43.8.9', '43.0.0', '42.4.0')]
        self.assertEqual(updates.supported_majors(rel), {43, 44, 45})
        rows = list(updates.electron_rows(apps + [('code', '/usr/share/code', '43.8.6', 150)], rel))
        self.assertEqual([(s, t) for t, s, _ in rows], [(WARN, 'com.example.Chat runs on Electron 32.3.0 (Chromium 128), which no longer gets security fixes'),
                                                         (INFO, 'code bundles Electron 43 (Chromium 150)')])
        self.assertEqual([s for _, s, _ in updates.electron_rows(apps, {})], [INFO])   # no release feed yet


if __name__ == '__main__':
    unittest.main()
