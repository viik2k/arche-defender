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
        self.assertEqual(browsers.copy_query(self.d / 'missing', 'SELECT 1'), [])

    def test_firefox_prefs(self):
        prof = self.d / 'ab12.default-release'; prof.mkdir()
        (prof / 'prefs.js').write_text('user_pref("browser.safebrowsing.malware.enabled", false);\nuser_pref("network.proxy.type", 1);\n'
                                       'user_pref("network.proxy.socks", "10.0.0.5");\nuser_pref("network.proxy.socks_port", 1080);\n')
        (prof / 'user.js').write_text('user_pref("browser.safebrowsing.phishing.enabled", false);\n')
        with mock.patch.object(browsers, 'chromium_profiles', return_value=[]), mock.patch.object(browsers, 'FIREFOX', [str(self.d)]):
            r = {t: s for t, s, _ in browsers.protection()}
        self.assertEqual(r['Firefox (default-release): Safe Browsing malware and phishing protection is off'], WARN)
        self.assertEqual(r['Firefox (default-release): sends traffic through a proxy (10.0.0.5:1080)'], INFO)

    def test_policies(self):
        r = {t.split(':')[0]: s for t, s, _ in browsers.policy_rows('Chrome', '/etc/x.json', {'ExtensionInstallForcelist': ['abc;https://x'], 'BrowserSignin': 0})}
        self.assertEqual(r, {'Chrome policy ExtensionInstallForcelist forces extensions you cannot remove': WARN, 'Chrome policy BrowserSignin': INFO})

    def test_nss(self):
        with mock.patch.object(browsers, 'sh', return_value=CERTUTIL):
            self.assertEqual(browsers.nss_cas('/x'), ['Evil Root CA'])


if __name__ == '__main__':
    unittest.main()
