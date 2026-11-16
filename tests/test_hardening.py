# Run: python3 tests/test_hardening.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.hardening import plain_swap, ssh_client_rows


def test_plain_swap():
    swaps = ('Filename\tType\tSize\tUsed\tPriority\n/dev/dm-1  partition\t36057084\t0\t-1\n/dev/zram0  partition\t8388604\t0\t100\n'
             '/dev/dm-3  partition\t100\t0\t-2\n/swapfile  file\t100\t0\t-3\n')
    layers = {'/dev/dm-1': ['lvm', 'disk', 'part'], '/dev/dm-3': ['crypt', 'part', 'disk']}
    assert plain_swap(swaps, lambda d: layers[d]) == ['/dev/dm-1']
    assert plain_swap('Filename\tType\tSize\tUsed\tPriority\n', lambda d: []) == []



def test_ssh_client_rows():
    t = ('ForwardAgent yes\nHost unix/* machine/*\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n'
         'Host lab\n  ForwardX11 yes\nHost *\n  StrictHostKeyChecking=accept-new\n  # ForwardX11 yes\nMatch final all\n  ForwardX11 yes\n')
    rows = [x for x, s, _ in ssh_client_rows(t, 'cfg') if s == 1]
    assert len(rows) == 2 and 'ForwardAgent yes' in rows[0] and 'ForwardX11 yes' in rows[1], rows   # per-host and accept-new are fine
    assert [s for _, s, _ in ssh_client_rows('Host *\n    UserKnownHostsFile "/dev/null"\n', 'cfg')] == [1]


def test_firewall_v6():
    import arche.hardening as h
    real = h.sh, h.have
    out = {'--get-active-zones': 'FedoraWorkstation (default)\n  interfaces: eno1\n',
           '--zone=FedoraWorkstation': '  target: default\n  services: ssh\n  ports: 1025-65535/tcp 1025-65535/udp\n'}
    for addr, tail in (('2403:5800:1::7', ', and from the internet over IPv6 unless your router blocks it'), ('fd00::7', '')):
        h.have, h.sh = (lambda c: True), lambda *a, **k: out.get(a[1], '') if a[0] == 'firewall-cmd' else f'2: eno1 inet6 {addr}/64 scope global'
        try: rows = [t for t, s, _ in h.firewall() if s == 1]
        finally: h.sh, h.have = real
        assert rows == [f'Zone FedoraWorkstation opens ports {p} to your network{tail}: any app that listens is reachable'
                        for p in ('1025-65535/tcp', '1025-65535/udp')], rows


def test_kube_rows():
    from arche.hardening import kube_rows
    t = ('apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: AAAA\n    server: https://192.168.4.130:6443\n  name: k3s\n'
         '- cluster:\n    insecure-skip-tls-verify: true\n    server: https://lab.example:6443\n  name: lab\n'
         '- cluster:\n    server: http://10.0.0.9:8080\n  name: old\nusers:\n- name: eks\n  user:\n    exec:\n'
         '      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [eks, get-token]\n')
    rows = [(r[0].split(':')[0] if r[1] else r[0], r[1]) for r in kube_rows(t, '~/.kube/config')]
    assert rows == [('~/.kube/config skips the TLS check for https', 1), ('~/.kube/config reaches http', 1),
                    ('~/.kube/config runs aws on every kubectl login (exec plugin)', 0)], rows


def test_polkit():
    import arche.hardening as h, tempfile, shutil, atexit
    d = tempfile.mkdtemp(); atexit.register(shutil.rmtree, d, True)
    for n, body in (('a.rules', 'polkit.addRule(function(a, s) { return polkit.Result.YES; });'), ('b.rules', 'return polkit.Result.AUTH_ADMIN;'), ('pkg.rules', 'Result.YES')):
        open(f'{d}/{n}', 'w').write(body)
    old = h.POLKIT, h.owned, h.sh
    h.POLKIT, h.owned, h.sh = (f'{d}/*.rules',), lambda ps: {p for p in ps if p.endswith('pkg.rules')}, lambda *a, **k: 'finn wheel empower'
    try: rows = [(r[0].replace(d, '~'), r[1]) for r in h.polkit_rows()]
    finally: h.POLKIT, h.owned, h.sh = old
    assert [s for _, s in rows] == [1, 0, 1] and rows[0][0].startswith('polkit rule ~/a.rules lets') and 'empower' in rows[2][0], rows


def test_browsed():
    from arche.hardening import browsed_rows
    assert [r[1] for r in browsed_rows(True, '# x\nBrowseRemoteProtocols dnssd cups\n')] == [1]
    assert list(browsed_rows(True, 'BrowseRemoteProtocols cups\nBrowseRemoteProtocols none\n')) == []
    assert list(browsed_rows(False, 'BrowseRemoteProtocols cups\n')) == [] and list(browsed_rows(True, '')) == []


if __name__ == '__main__':
    test_browsed(); test_polkit(); test_kube_rows(); test_firewall_v6(); test_plain_swap(); test_ssh_client_rows(); print('ok')
