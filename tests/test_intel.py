import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import hashlib, io, unittest
from unittest import mock
from arche import intel


def parsed(kind, body):
    out = {'ips': {}, 'nets': [], 'domains': {}, 'hashes': {}, 'urls': {}}
    intel._parse(kind, body, 'feed', out)
    return out


class Parse(unittest.TestCase):
    def test_kinds(self):
        self.assertIn('1.2.3.4', parsed('ip', '# header\n1.2.3.4\n\n')['ips'])
        self.assertEqual(str(parsed('net', '{"cidr":"1.10.16.0/20","sblid":"x"}\n')['nets'][0][0]), '1.10.16.0/20')
        h = parsed('hash', 'AB' * 32 + ';Some Family\n')['hashes']
        self.assertEqual(h['ab' * 32], 'feed: Some Family')
        m = parsed('mixed', 'evil.example\n5.6.7.8\n')
        self.assertIn('evil.example', m['domains']); self.assertIn('5.6.7.8', m['ips'])
        self.assertIn('bad.test', parsed('domain', '*.bad.test\n')['domains'])
        c = parsed('custom', '10.9.8.0/24\nsome.host.example\n' + 'c' * 40 + '\n')
        self.assertTrue(c['nets'] and c['domains'] and c['hashes'])


URLHAUS = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs)           #
# Last updated: 2026-11-16 10:00:00 (UTC)                      #
#                                                              #
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3300001","2026-11-16 09:00:00","https://raw.githubusercontent.com/bad/repo/main/x.sh","online","2026-11-16 09:00:00","malware_download","sh","https://urlhaus.abuse.ch/url/3300001/","someone"
"3300002","2026-11-16 09:01:00","http://203.0.113.7:8080/i","online","","malware_download","Mozi","https://urlhaus.abuse.ch/url/3300002/","someone"
"""
BAZAAR = """# MalwareBazaar recent
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
"2026-11-16 09:00:00", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccccccccccc", "x", "y.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "n/a", "n/a", "n/a", "n/a"
"""
THREATFOX = """# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"
"2026-11-16 08:00:00", "1", "198.51.100.9:443", "ip:port", "botnet_cc", "win.cobalt_strike", "None", "Cobalt Strike", "", "100", "https://twitter.com/x", "None", "0", "someone"
"2026-11-16 08:00:00", "2", "c2.bad.example", "domain", "botnet_cc", "win.x", "None", "Unknown malware", "", "100", "https://blog.example.org/a", "None", "0", "someone"
"""


class AbuseCh(unittest.TestCase):
    def test_csv_exports(self):
        u, b, t = parsed('abusech', URLHAUS), parsed('abusech', BAZAAR), parsed('abusech', THREATFOX)
        self.assertEqual(u['urls']['https://raw.githubusercontent.com/bad/repo/main/x.sh'], 'feed: malware_download')
        self.assertNotIn('raw.githubusercontent.com', u['domains'])        # shared hosts are never listed whole
        self.assertNotIn('urlhaus.abuse.ch', u['domains'])
        self.assertIn('203.0.113.7', u['ips'])
        self.assertEqual(b['hashes']['a' * 64], 'feed: AgentTesla'); self.assertIn('b' * 32, b['hashes'])
        self.assertEqual(t['ips']['198.51.100.9'], 'feed: Cobalt Strike')
        self.assertEqual(t['domains']['c2.bad.example'], 'feed: Unknown malware')
        self.assertNotIn('twitter.com', t['domains']); self.assertNotIn('blog.example.org', t['domains'])
        self.assertEqual(parsed('abusech', 'no header\n"1","2","3","4","5"\n'), parsed('abusech', ''))

    def test_host(self):
        self.assertEqual(intel._host('https://user@Evil.Example.com:8080/x?y'), 'evil.example.com')
        self.assertEqual(intel._host('http://[2001:db8::1]/a'), '2001:db8::1')


class Lookup(unittest.TestCase):
    def setUp(self):
        out = parsed('mixed', '8.8.4.4\nexample.org\n'); intel._parse('net', '{"cidr":"1.10.16.0/20"}', 'drop', out)
        p = mock.patch.object(intel, 'load', return_value=out); p.start(); self.addCleanup(p.stop)

    def test_ip(self):
        self.assertEqual(intel.ip_hit('8.8.4.4'), 'feed')
        self.assertEqual(intel.ip_hit('1.10.20.1'), 'drop')
        self.assertIsNone(intel.ip_hit('192.168.1.1'))
        self.assertIsNone(intel.ip_hit('not an ip'))

    def test_domain_parents(self):
        self.assertEqual(intel.domain_hit('a.b.example.org'), 'feed')
        self.assertIsNone(intel.domain_hit('example.com'))
        self.assertIsNone(intel.domain_hit('org'))

    def test_url(self):
        intel.load()['urls']['http://x.example/a'] = 'urlhaus'
        self.assertEqual(intel.url_hit('HTTP://x.example/a/'), 'urlhaus')
        self.assertIsNone(intel.url_hit('http://x.example/b'))


if __name__ == '__main__':
    unittest.main()


class PasswordCheck(unittest.TestCase):
    def test_range(self):
        h = hashlib.sha1(b'hunter2').hexdigest().upper()
        body = f'{"0" * 35}:0\r\n{h[5:]}:17043\r\nABCDEF0123456789ABCDEF0123456789ABC:3\r\n'.encode()
        seen = {}
        class R(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): pass
        def fake(req, timeout): seen['url'] = req.full_url; return R(body)
        with mock.patch('urllib.request.urlopen', fake):
            self.assertIn('17,043 times', intel.password_check('hunter2'))
            self.assertEqual(seen['url'], f'https://api.pwnedpasswords.com/range/{h[:5]}')
            self.assertTrue(intel.password_check('something else entirely').startswith('Not in any known breach'))
