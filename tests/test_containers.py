# Run: python3 tests/test_containers.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.containers import container_rows, daemon_rows
from arche.core import HOME


def test_container_rows():
    info = [{'Name': '/miner', 'Config': {'Image': 'x/xmrig'}, 'HostConfig': {'Privileged': True, 'PidMode': 'host',
             'RestartPolicy': {'Name': 'always'}, 'CapAdd': ['CAP_SYS_ADMIN', 'NET_RAW'], 'SecurityOpt': ['apparmor=unconfined']},
             'Mounts': [{'Source': '/', 'RW': True}, {'Source': '/var/run/docker.sock', 'RW': False}]},
            {'Name': '/exporter', 'Config': {'Image': 'prom/node-exporter'}, 'HostConfig': {'NetworkMode': 'host'},
             'Mounts': [{'Source': '/', 'RW': False}, {'Source': f'{HOME}/code/app', 'RW': True}]}]
    rows = list(container_rows(info))
    assert [(t, s) for t, s, _ in rows if s == 0] == [('Container miner (x/xmrig), restarts by itself', 0), ('Container exporter (prom/node-exporter)', 0)]
    bad = [t for t, s, _ in rows if s]
    assert len(bad) == 1 and all(x in bad[0] for x in ('privileged', 'docker.sock', 'write to /', 'every process', 'SYS_ADMIN',
                                                         'apparmor=unconfined')) and 'NET_RAW' not in bad[0], bad


def test_daemon_rows():
    assert [s for _, s, _ in daemon_rows({'hosts': ['unix:///var/run/docker.sock', 'tcp://0.0.0.0:2375']}, '', 0o140660)] == [2]
    assert list(daemon_rows({'hosts': ['tcp://0.0.0.0:2376'], 'tlsverify': True}, '', 0o140660)) == []
    assert [s for _, s, _ in daemon_rows({}, 'ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375', 0o140666)] == [2, 2]
    assert list(daemon_rows({}, 'ExecStart=/usr/bin/dockerd -H fd://', None)) == []
    assert [s for _, s, _ in daemon_rows({'insecure-registries': ['10.0.0.5:5000']}, '', None)] == [1]


if __name__ == '__main__':
    test_container_rows(); test_daemon_rows(); print('ok')
