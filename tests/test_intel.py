import unittest
from unittest import mock
from arche import intel


def parsed(kind, body):
    out = {'ips': {}, 'nets': [], 'domains': {}, 'hashes': {}}
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


if __name__ == '__main__':
    unittest.main()
