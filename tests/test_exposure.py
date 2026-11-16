import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import tempfile, unittest
from unittest import mock
from arche import exposure
from arche.core import WARN, INFO

SS = '''udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:*
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
udp UNCONN 0 0 224.0.0.251:5353 0.0.0.0:* users:(("steamwebhelper",pid=9545,fd=210))
udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*
udp UNCONN 0 0 *:1716 *:* users:(("kdeconnectd",pid=3264,fd=16))
tcp LISTEN 0 4096 127.0.0.1:11434 0.0.0.0:*
tcp LISTEN 0 512 0.0.0.0:27036 0.0.0.0:* users:(("steam",pid=9522,fd=154))
tcp LISTEN 0 4096 100.99.130.92%tailscale0:52093 0.0.0.0:*
tcp LISTEN 0 4096 [::]:6379 [::]:* users:(("redis-server",pid=1,fd=6))
tcp LISTEN 0 4096 [::1]:631 [::]:*
'''


class Exposed(unittest.TestCase):
    def test_listening(self):
        self.assertEqual(list(exposure.listening(SS)), [('udp', 5353, 'mdns (system service)'), ('udp', 1716, 'kdeconnectd'),
                                                        ('tcp', 27036, 'steam'), ('tcp', 6379, 'redis-server')])

    def test_firewall_filter(self):
        ls = list(exposure.listening(SS))
        rules = exposure.port_specs('5353/udp 1025-65535/tcp')
        self.assertEqual([(s, t) for t, s, _ in exposure.exposed_rows(ls, rules)],
                         [(INFO, 'Reachable from your network: mdns (system service) on udp port 5353'),
                          (INFO, 'Reachable from your network: steam on tcp port 27036'),
                          (WARN, 'Redis (redis-server) on tcp port 6379 is reachable from your network')])
        self.assertEqual(len(list(exposure.exposed_rows(ls, None))), 4)
        self.assertEqual(list(exposure.exposed_rows(ls, [])), [])

    def test_service_ports(self):
        with tempfile.TemporaryDirectory() as etc, tempfile.TemporaryDirectory() as lib:
            for d, name, body in ((lib, 'samba-client', '<include service="netbios-ns"/><port protocol="udp" port="138"/>'),
                                  (lib, 'netbios-ns', '<port protocol="udp" port="137"/>'), (lib, 'loop', '<include service="loop"/>'),
                                  (lib, 'kde', '<port protocol="tcp" port="1714-1764"/>'), (etc, 'kde', '<port protocol="tcp" port="1714"/>')):
                with open(f'{d}/{name}.xml', 'w') as f: f.write(f'<service>{body}</service>')
            with mock.patch.object(exposure, 'FW_SERVICES', (etc, lib)), mock.patch.object(exposure, 'sh', return_value='  ports: 9/udp\n'):
                self.assertEqual(exposure.port_specs(exposure.service_ports('samba-client')), [('udp', 138, 138), ('udp', 137, 137)])
                self.assertEqual(exposure.service_ports('kde'), '1714/tcp')
                self.assertEqual(exposure.service_ports('loop'), '')
                self.assertEqual(exposure.service_ports('custom'), '9/udp')

    def test_docker(self):
        rows = list(exposure.docker_rows('web\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\ndb\t127.0.0.1:5432->5432/tcp\nold\t:::9000->9000/tcp'))
        self.assertEqual([t for t, _, _ in rows], ['Container web publishes port 8080 (80/tcp) to your whole network: Docker bypasses firewalld',
                                                   'Container old publishes port 9000 (9000/tcp) to your whole network: Docker bypasses firewalld'])
        self.assertIn('127.0.0.1:8080:80', rows[0][2])


DESC = b'''<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceList><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>http://evil.example/x</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/ctl/L3F</controlURL></service>
</serviceList></device></deviceList></device></root>'''


class Upnp(unittest.TestCase):
    def test_services_same_host_only(self):
        self.assertEqual(list(exposure.wan_services(DESC, 'http://192.168.1.1:5000/rootDesc.xml')),
                         [('urn:schemas-upnp-org:service:WANIPConnection:1', 'http://192.168.1.1:5000/ctl/IPConn')])

    def test_rows(self):
        maps = [{'NewProtocol': 'TCP', 'NewExternalPort': '3389', 'NewInternalClient': '192.168.1.20', 'NewInternalPort': '3389', 'NewPortMappingDescription': 'x'},
                {'NewProtocol': 'UDP', 'NewExternalPort': '3074', 'NewInternalClient': '192.168.1.30', 'NewInternalPort': '3074'},
                {'NewProtocol': 'TCP', 'NewExternalPort': '1', 'NewInternalClient': '192.168.1.20', 'NewEnabled': '0'}]
        rows = list(exposure.mapping_rows('192.168.1.1', maps, {'192.168.1.20'}))
        self.assertEqual([s for _, s, _ in rows], [INFO, WARN, INFO])
        self.assertEqual(rows[1][0], 'The router forwards TCP port 3389 to 192.168.1.20:3389 (x) from the internet to this PC')


class Gateway(unittest.TestCase):
    def test_spoof(self):
        neigh = {'192.168.1.1': '08:9b:f1:08:1d:8d', '192.168.1.50': '08:9b:f1:08:1d:8d', '192.168.1.9': 'bc:24:11:cc:8c:00'}
        rows = list(exposure.gateway_rows('192.168.1.1', neigh))
        self.assertEqual([s for _, s, _ in rows], [WARN, INFO])
        self.assertTrue(rows[0][0].startswith('192.168.1.50 answers'))
        self.assertEqual([s for _, s, _ in exposure.gateway_rows('192.168.1.1', {'192.168.1.1': 'aa:bb:cc:dd:ee:ff'})], [INFO])
        self.assertEqual(list(exposure.gateway_rows('192.168.1.1', {})), [])
        self.assertEqual(exposure.maker('02:00:00:00:00:01'), 'randomised or virtual address')


class Tunnels(unittest.TestCase):
    def test_ssh_reverse(self):
        R = exposure.ssh_reverse
        self.assertEqual(R(['ssh', '-R', '80:localhost:8080', 'serveo.net']), 'serveo.net')
        self.assertEqual(R(['ssh', '-p', '443', '-NfR0:localhost:3000', 'a.pinggy.io']), 'a.pinggy.io')
        self.assertEqual(R(['ssh', '-oServerAliveInterval=30', '-NR', '9000:localhost:22', 'me@vps.example']), 'me@vps.example')
        self.assertIsNone(R(['ssh', '-L', '8080:localhost:80', 'host']))
        self.assertIsNone(R(['ssh', 'host', 'ls', '-R']))   # -R of the remote command

    def test_rows(self):
        procs = [('10', ['/usr/bin/cloudflared', '--no-autoupdate', 'tunnel', 'run', '--token', 'eyJx']),
                 ('11', ['/usr/bin/cloudflared', 'proxy-dns']),                 # a DNS-over-HTTPS proxy, not a tunnel
                 ('12', ['/opt/playit/playit-linux-amd64']), ('13', ['ssh', '-R', '80:localhost:80', 'nokey@localhost.run']),
                 ('14', ['ssh', '-NR', '2222:localhost:22', 'me@vps.example']), ('15', [])]
        r = [(t, s) for t, s, _ in exposure.tunnel_rows(procs)]
        self.assertEqual(r, [('Cloudflare Tunnel is publishing a port on this PC to the internet (process 10: /usr/bin/cloudflared)', WARN),
                             ('playit.gg is publishing a port on this PC to the internet (process 12: /opt/playit/playit-linux-amd64)', WARN),
                             ('ssh -R is publishing a port on this PC to the internet through nokey@localhost.run (process 13)', WARN),
                             ('SSH reverse tunnel (ssh -R): me@vps.example can reach into this PC', INFO)])
        self.assertFalse(any('eyJx' in t for t, _ in r))   # tokens on the command line stay hidden

    def test_tailscale(self):
        serve = {'TCP': {'443': {'HTTPS': True}, '8443': {'HTTPS': True}}, 'AllowFunnel': {'pc.tail1234.ts.net:443': True},
                 'Foreground': {'abc': {'TCP': {'10000': {'HTTPS': True}}, 'AllowFunnel': {'pc.tail1234.ts.net:10000': True}}}}
        prefs = {'RunSSH': True, 'AdvertiseRoutes': ['192.168.4.0/24', '0.0.0.0/0', '::/0'], 'ExitNodeID': '', 'DriveShares': [{'Name': 'docs'}]}
        r = [(t, s) for t, s, _ in exposure.tailscale_rows(prefs, serve)]
        self.assertEqual(r, [('Tailscale Funnel publishes ports 443, 10000 on this PC to the whole internet', WARN),
                             ('Tailscale Serve shares port 8443 with your tailnet', INFO),
                             ('Tailscale SSH is on: devices your tailnet policy allows can log in to this PC', INFO),
                             ('This PC offers itself as a Tailscale exit node for your tailnet', INFO),
                             ('This PC routes your tailnet into 192.168.4.0/24 (subnet router)', INFO),
                             ('Taildrive shares docs with your tailnet', INFO)])
        self.assertEqual(list(exposure.tailscale_rows({'ShieldsUp': False}, {})), [])


if __name__ == '__main__': unittest.main()
