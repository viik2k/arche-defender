import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import base64, json, shutil, sqlite3, tempfile, unittest
from pathlib import Path
from unittest import mock
from arche import browsers
from arche.core import ALERT, WARN, INFO

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
        con = sqlite3.connect(prof / 'Web Data'); con.execute('CREATE TABLE credit_cards (card_number_encrypted BLOB)')
        con.execute("INSERT INTO credit_cards VALUES (x'7631300102')"); con.commit(); con.close()
        with mock.patch.object(browsers, 'chromium_profiles', return_value=[('Brave', str(prof))]), mock.patch.object(browsers, 'FIREFOX', []):
            self.assertEqual([t for t, _, _ in browsers.protection()][1], 'Brave: its sign-in cookies and 1 saved payment card are protected only by a built-in key')
        self.assertEqual(browsers.copy_query(self.d / 'missing', 'SELECT 1'), [])

    def test_password_checkup(self):
        prof = self.d / 'Default'; prof.mkdir()
        con = sqlite3.connect(prof / 'Login Data')
        con.execute('CREATE TABLE insecure_credentials (parent_id, insecurity_type, create_time, is_muted)')
        con.executemany('INSERT INTO insecure_credentials VALUES (?, ?, 0, ?)', [(1, 0, 0), (2, 0, 0), (3, 0, 1), (1, 1, 0), (4, 2, 0)]); con.commit(); con.close()
        with mock.patch.object(browsers, 'chromium_profiles', return_value=[('Chrome', str(prof))]), mock.patch.object(browsers, 'FIREFOX', []):
            r = [(t, s) for t, s, _ in browsers.protection()]
        self.assertEqual(r, [('Chrome: 2 saved passwords were found in a data breach', WARN), ('Chrome: 1 saved password was entered on a phishing site', ALERT)])

    def test_site_permissions(self):
        prof = self.d / 'Default'; prof.mkdir()
        ex = {'notifications': {'https://[*.]news.example:443,*': {'setting': 1}, 'https://robot-check.example:443,*': {'setting': 1},
                                'https://blocked.example:443,*': {'setting': 2}},
              'media_stream_camera': {'https://meet.example:443,*': {'setting': 1}}, 'cookies': {'https://x.example:443,*': {'setting': 1}}}
        (prof / 'Preferences').write_text(json.dumps({'profile': {'content_settings': {'exceptions': ex}}}))
        ff = self.d / 'ab12.default-release'; ff.mkdir()
        con = sqlite3.connect(ff / 'permissions.sqlite'); con.execute('CREATE TABLE moz_perms (origin, type, permission)')
        con.executemany('INSERT INTO moz_perms VALUES (?, ?, ?)', [('https://maps.example^userContextId=2', 'geo', 1), ('https://ads.example', 'desktop-notification', 2)])
        con.commit(); con.close()
        hit = lambda h: 'HaGeZi TIF' if h == 'robot-check.example' else None
        with mock.patch.object(browsers, 'chromium_profiles', return_value=[('Brave', str(prof))]), mock.patch.object(browsers, 'FIREFOX', [str(self.d)]), \
             mock.patch('arche.intel.domain_hit', hit):
            r = [(t, s) for t, s, _ in browsers.site_permissions()]
        self.assertEqual(r, [('Brave: robot-check.example may send you notifications and is on threat list HaGeZi TIF', ALERT),
                             ('Brave: 2 sites may send you notifications: news.example, robot-check.example', INFO),
                             ('Brave: 1 site may use your camera: meet.example', INFO),
                             ('Firefox (default-release): 1 site may see your location: maps.example', INFO)])

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

    def test_firefox_primary_password(self):
        prof = self.d / 'ab12.default-release'; prof.mkdir(); (prof / 'prefs.js').write_text('')
        (prof / 'logins.json').write_text(json.dumps({'logins': [{}, {}]}))
        def key4(rounds):   # the start of what certutil writes: PBES2, then PBKDF2 with a 32-byte salt and the round count
            (prof / 'key4.db').unlink(missing_ok=True); con = sqlite3.connect(prof / 'key4.db')
            r = rounds.to_bytes(1 if rounds < 128 else 2, 'big')
            item2 = bytes.fromhex('308181306d06092a864886f70d01050d3060304106092a864886f70d01050c3034') + b'\x04\x20' + bytes(32) + bytes([2, len(r)]) + r
            con.execute('CREATE TABLE metaData (id PRIMARY KEY, item1, item2)'); con.execute("INSERT INTO metaData VALUES ('password', x'00', ?)", (item2,))
            con.commit(); con.close()
            with mock.patch.object(browsers, 'chromium_profiles', return_value=[]), mock.patch.object(browsers, 'FIREFOX', [str(self.d)]):
                return [t for t, _, _ in browsers.protection()]
        self.assertEqual(key4(1), ['Firefox (default-release): 2 saved passwords are not protected by a Primary Password'])
        self.assertEqual(key4(10000), [])

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


class Discord(unittest.TestCase):
    def test_token(self):
        uid = base64.urlsafe_b64encode(b'123456789012345678').rstrip(b'=')
        fake = b'_https://discord.com\x00\x01token\x01"' + uid + b'.GhIjKl.' + b'a' * 38 + b'"'
        self.assertTrue(browsers.discord_token(fake))
        self.assertTrue(browsers.discord_token(b'"dQw4w9WgXcQ:djEwAAAA"'))
        self.assertFalse(browsers.discord_token(b'"dQw4w9WgXcQ:djExAAAA"'))   # v11: under the keyring
        self.assertFalse(browsers.discord_token(b'"' + base64.urlsafe_b64encode(b'not-a-user-id-xx') + b'.GhIjKl.' + b'a' * 38 + b'"'))
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d)
        (d / 'Local Storage/leveldb').mkdir(parents=True); (d / 'Local Storage/leveldb/000005.ldb').write_bytes(fake)
        with mock.patch.object(browsers, 'DISCORD', {str(d): 'Discord (Flatpak)'}):
            self.assertEqual([(t, s) for t, s, _ in browsers.sign_ins()], [('Discord (Flatpak) keeps your sign-in token where any program can read it', INFO)])

    def test_server_passwords(self):
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d)
        (d / 'sitemanager.xml').write_text('<Server><Pass encoding="base64">aHVudGVyMg==</Pass></Server><Server><Pass encoding="crypt" pubkey="x">y</Pass></Server>')
        (d / 'a.remmina').write_text('[remmina]\npassword=.\n'); (d / 'b.remmina').write_text('[remmina]\npassword=\n')
        (d / 'c.remmina').write_text('[remmina]\npassword=Zm9vYmFy\n')
        with mock.patch.multiple(browsers, DISCORD={}, FILEZILLA=(str(d),), REMMINA=(f'{d}/*.remmina',)):
            self.assertEqual([(t, s) for t, s, _ in browsers.sign_ins()], [('FileZilla keeps 1 server password in plain text (sitemanager.xml)', WARN),
                                                                           ('Remmina keeps 1 connection password that any program can decrypt', WARN)])


class CopyQuery(unittest.TestCase):
    def test_reads_rows_still_in_the_wal(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        con = sqlite3.connect(f'{d}/h.sqlite'); self.addCleanup(con.close)   # left open, as a running app keeps it
        con.executescript('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t (x); INSERT INTO t VALUES (1), (2);')
        self.assertTrue(os.path.exists(f'{d}/h.sqlite-wal'))
        self.assertEqual(browsers.copy_query(f'{d}/h.sqlite', 'SELECT x FROM t'), [(1,), (2,)])


if __name__ == '__main__':
    unittest.main()


class Unpacked(unittest.TestCase):
    def test_rows(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        prof, ext, own = f'{d}/Default', f'{d}/dl/ext', f'{d}/code/myext/src'
        for p in (prof, ext, own, f'{d}/code/myext/.git'): os.makedirs(p)
        with open(f'{ext}/manifest.json', 'w') as f: json.dump({'name': 'PDF Helper'}, f)
        with open(f'{prof}/Preferences', 'w') as f:
            json.dump({'extensions': {'settings': {'a' * 32: {'location': 4, 'path': ext}, 'b' * 32: {'location': 8, 'path': f'{d}/gone'},
                                                   'c' * 32: {'location': 4, 'path': own, 'manifest': {'name': 'Mine'}},
                                                   'd' * 32: {'location': 8, 'path': '/usr/share', 'manifest': {'name': 'Bundled'}},
                                                   'e' * 32: {'location': 1, 'path': 'eeee/1.0'}}}}, f)
        rows = [(s, t) for t, s, _ in browsers.unpacked_rows('Chrome', prof)]
        self.assertEqual(rows, [(WARN, f'Chrome: extension "PDF Helper" is loaded from a folder, not from the store: {ext}')])


class Hijack(unittest.TestCase):
    def test_prefs(self):
        tpl = lambda url, pid: {'default_search_provider_data': {'mirrored_template_url_data': {'url': url, 'prepopulate_id': pid}}}
        rows = lambda prefs: [(s, t) for t, s, _ in browsers.hijack_rows('Brave', prefs)]
        self.assertEqual(rows(tpl('https://search.brave.com/search?q={searchTerms}', 550)), [])
        self.assertEqual(rows(tpl('https://searx.example/?q={searchTerms}', 0)), [(INFO, 'Brave: searches go to searx.example')])
        self.assertEqual(rows(tpl('http://search.example/?q={searchTerms}', 0)), [(WARN, 'Brave: searches go to search.example without encryption')])
        self.assertEqual(rows(tpl('https://www.google.com.search-hub.ru/?q={searchTerms}', 0))[0][0], ALERT)
        start = {'session': {'restore_on_startup': 4, 'startup_urls': ['https://news.example/']}, 'homepage': 'https://home.example/',
                 'homepage_is_newtabpage': False}
        self.assertEqual(rows(start), [(INFO, 'Brave: start page is news.example'), (INFO, 'Brave: home page is home.example')])
        self.assertEqual(rows({'session': {'restore_on_startup': 1, 'startup_urls': ['https://x.example/']}, 'homepage': 'https://y.example/'}), [])

    def test_extension_overrides(self):
        m = {'chrome_settings_overrides': {'search_provider': {'search_url': 'https://find.example/s?q={searchTerms}'},
                                           'startup_pages': ['https://find.example/']}}
        rows = [(s, t) for t, s, _ in browsers.override_rows([('Chrome', 'Better Search', 'a' * 32, m), ('Chrome', 'Plain', 'b' * 32, {})])]
        self.assertEqual(rows, [(INFO, 'Chrome: extension "Better Search" sends your searches to find.example'),
                                (INFO, 'Chrome: extension "Better Search" sets the start page to find.example')])
