import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import json, shutil, sqlite3, tempfile, unittest
from pathlib import Path
from unittest import mock
from arche import browsers
from arche.core import WARN, INFO

CERTUTIL = """
Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

Evil Root CA                                                 CT,C,C
DigiCert SHA2 Intermediate                                   ,,   
My Client Cert                                               u,u,u
"""


class Browsers(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.d, True)

    def test_chromium_profile(self):
        prof = self.d / 'Default'; prof.mkdir()
        (prof / 'Preferences').write_text(json.dumps({'safebrowsing': {'enabled': False}}))
        con = sqlite3.connect(prof / 'Login Data')
        con.execute('CREATE TABLE logins (password_value BLOB)')
        con.executemany('INSERT INTO logins VALUES (?)', [(b'v10xx',), (b'v10yy',), (b'v11zz',)]); con.commit(); con.close()
        with mock.patch.object(browsers, 'chromium_profiles', return_value=[('Brave', str(prof))]), mock.patch.object(browsers, 'FIREFOX', []):
            r = [(t, s) for t, s, _ in browsers.protection()]
        self.assertEqual(r, [('Brave: Safe Browsing is off', WARN), ('Brave: 2 saved passwords are protected only by a built-in key', WARN)])
        con = sqlite3.connect(prof / 'Cookies')
        con.execute('CREATE TABLE cookies (encrypted_value BLOB)'); con.execute("INSERT INTO cookies VALUES (x'7631300102')"); con.commit(); con.close()
        (prof / 'Login Data').unlink()
        with mock.patch.object(browsers, 'chromium_profiles', return_value=[('Brave', str(prof))]), mock.patch.object(browsers, 'FIREFOX', []):
            self.assertEqual([t for t, _, _ in browsers.protection()][1], 'Brave: its sign-in cookies are protected only by a built-in key')
        self.assertEqual(browsers.copy_query(self.d / 'missing', 'SELECT 1'), [])

    def test_firefox_prefs(self):
        prof = self.d / 'ab12.default-release'; prof.mkdir()
        (prof / 'prefs.js').write_text('user_pref("browser.safebrowsing.malware.enabled", false);\nuser_pref("network.proxy.type", 1);\n'
                                       'user_pref("network.proxy.socks", "10.0.0.5");\nuser_pref("network.proxy.socks_port", 1080);\n')
        (prof / 'user.js').write_text('user_pref("browser.safebrowsing.phishing.enabled", false);\nuser_pref("xpinstall.signatures.required", false);\n'
                                      'user_pref("security.tls.version.min", 3);\nuser_pref("security.cert_pinning.enforcement_level", 0);\n')
        with mock.patch.object(browsers, 'chromium_profiles', return_value=[]), mock.patch.object(browsers, 'FIREFOX', [str(self.d)]):
            r = {t: s for t, s, _ in browsers.protection()}
        self.assertEqual(r['Firefox (default-release): Safe Browsing malware and phishing protection is off'], WARN)
        self.assertEqual(r['Firefox (default-release): sends traffic through a proxy (10.0.0.5:1080)'], INFO)
        self.assertEqual(r["Firefox (default-release) installs extensions without Mozilla's signature check (xpinstall.signatures.required = false)"], WARN)
        self.assertEqual(r['Firefox (default-release) has certificate pinning off (security.cert_pinning.enforcement_level = 0)'], WARN)
        self.assertFalse(any('TLS' in t for t in r))

    def test_launch_flags(self):
        F = lambda *a: [f for f, _ in browsers.launch_flags(['chrome', *a])]
        self.assertEqual(F('--remote-debugging-port=9222'), ['--remote-debugging-port'])                       # default profile
        self.assertEqual(F('--remote-debugging-port=9222', '--user-data-dir=/tmp/playwright_x'), [])            # throwaway profile
        self.assertEqual(F('--remote-debugging-port=0', '--user-data-dir=~/.config/google-chrome'), ['--remote-debugging-port'])
        self.assertEqual(F('--load-extension=/tmp/x', '--load-extension=/tmp/y', '--no-sandbox'), ['--load-extension'])
        apps = self.d / '.local/share/applications'; apps.mkdir(parents=True)
        (apps / 'chrome.desktop').write_text('[Desktop Entry]\nExec=/usr/bin/google-chrome-stable --load-extension=/home/u/.x %U\n')
        (apps / 'brave.desktop').write_text('[Desktop Entry]\nExec=flatpak run com.brave.Browser --proxy-server=socks5://1.2.3.4:1080\n')
        (apps / 'other.desktop').write_text('[Desktop Entry]\nExec=myapp --load-extension=x\n')
        (self.d / '.config').mkdir(); (self.d / '.config/chromium-flags.conf').write_text('# --load-extension=old\n--ignore-certificate-errors\n')
        with mock.patch.object(browsers, 'HOME', str(self.d)), mock.patch.object(browsers, 'argv', return_value=[]):
            r = sorted((s, t.split(' with ')[1].split(':')[0]) for t, s, _ in browsers.flags())
        self.assertEqual(r, [(INFO, '--proxy-server'), (WARN, '--ignore-certificate-errors'), (WARN, '--load-extension')])

    def test_policies(self):
        r = {t.split(':')[0]: s for t, s, _ in browsers.policy_rows('Chrome', '/etc/x.json', {'ExtensionInstallForcelist': ['abc;https://x'], 'BrowserSignin': 0})}
        self.assertEqual(r, {'Chrome policy ExtensionInstallForcelist forces extensions you cannot remove': WARN, 'Chrome policy BrowserSignin': INFO})

    def test_nss(self):
        with mock.patch.object(browsers, 'sh', return_value=CERTUTIL):
            self.assertEqual(browsers.nss_cas('/x'), ['Evil Root CA'])


class CopyQuery(unittest.TestCase):
    def test_reads_rows_still_in_the_wal(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        con = sqlite3.connect(f'{d}/h.sqlite'); self.addCleanup(con.close)   # left open, as a running app keeps it
        con.executescript('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t (x); INSERT INTO t VALUES (1), (2);')
        self.assertTrue(os.path.exists(f'{d}/h.sqlite-wal'))
        self.assertEqual(browsers.copy_query(f'{d}/h.sqlite', 'SELECT x FROM t'), [(1,), (2,)])


if __name__ == '__main__':
    unittest.main()
