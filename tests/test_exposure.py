import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import unittest
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


if __name__ == '__main__': unittest.main()
