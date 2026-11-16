# Run: python3 tests/test_containers.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.containers import container_rows, daemon_rows, config_risks, devcontainer_text, client_rows
from arche.core import HOME


def test_container_rows():
    info = [{'Name': '/miner', 'Config': {'Image': 'x/xmrig'}, 'HostConfig': {'Privileged': True, 'PidMode': 'host',
             'RestartPolicy': {'Name': 'always'}, 'Devices': [{'PathOnHost': '/dev/nvme0n1'}], 'CapAdd': ['CAP_SYS_ADMIN', 'NET_RAW'], 'SecurityOpt': ['apparmor=unconfined']},
             'Mounts': [{'Source': '/', 'RW': True}, {'Source': '/var/run/docker.sock', 'RW': False}]},
            {'Name': '/exporter', 'Config': {'Image': 'prom/node-exporter'}, 'HostConfig': {'NetworkMode': 'host', 'Devices': [{'PathOnHost': '/dev/dri/card0'}]},
             'Mounts': [{'Source': '/', 'RW': False}, {'Source': f'{HOME}/code/app', 'RW': True}]}]
    rows = list(container_rows(info))
    assert [(t, s) for t, s, _ in rows if s == 0] == [('Container miner (x/xmrig), restarts by itself', 0), ('Container exporter (prom/node-exporter)', 0)]
    bad = [t for t, s, _ in rows if s]
    assert len(bad) == 1 and all(x in bad[0] for x in ('privileged', 'docker.sock', 'write to /', 'every process', 'SYS_ADMIN',
                                                         'apparmor=unconfined', 'raw device /dev/nvme0n1')) and 'NET_RAW' not in bad[0], bad


def test_daemon_rows():
    assert [s for _, s, _ in daemon_rows({'hosts': ['unix:///var/run/docker.sock', 'tcp://0.0.0.0:2375']}, '', 0o140660)] == [2]
    assert list(daemon_rows({'hosts': ['tcp://0.0.0.0:2376'], 'tlsverify': True}, '', 0o140660)) == []
    assert [s for _, s, _ in daemon_rows({}, 'ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375', 0o140666)] == [2, 2]
    assert list(daemon_rows({}, 'ExecStart=/usr/bin/dockerd -H fd://', None)) == []
    assert [s for _, s, _ in daemon_rows({'insecure-registries': ['10.0.0.5:5000']}, '', None)] == [1]


def test_config_risks():
    y = ('services:\n  a:\n    privileged: true\n    pid: host\n    cap_add:\n      - SYS_ADMIN\n      - NET_ADMIN\n    cap_drop:\n      - ALL\n'
         '    volumes:\n      - /:/host:ro\n      - /var/run/docker.sock:/var/run/docker.sock\n      - ~/.ssh:/root/.ssh\n      - ~/code/app:/app\n'
         '    devices:\n      - /dev/sda:/dev/sda\n      - /dev/dri:/dev/dri\n    security_opt:\n      - apparmor:unconfined\n')
    assert config_risks(y) == ['runs privileged (root on this PC)', 'can drive the container engine through its socket (root on this PC)',
                               'sees and can signal every process on this PC', 'mounts / from this PC', 'mounts ~/.ssh from this PC',
                               'gets the raw device /dev/sda', 'turns its confinement off', 'adds SYS_ADMIN'], config_risks(y)
    assert config_risks('services:\n  web:\n    cap_drop: [ALL]\n    volumes:\n      - ./site:/srv:ro\n      - /dev/dri:/dev/dri\n') == []
    dc = devcontainer_text({'runArgs': ['--cap-add=SYS_PTRACE'], 'mounts': [{'source': '/', 'target': '/host', 'type': 'bind'}, 'source=/tmp,target=/t']})
    assert config_risks(dc) == ['mounts / from this PC', 'adds SYS_PTRACE'], config_risks(dc)


def test_client_rows():
    rows = list(client_rows([('DOCKER_HOST', 'tcp://10.0.0.5:2375', None), ('DOCKER_HOST', 'tcp://10.0.0.5:2376', '1'),
                             ('Docker context nas', 'ssh://me@nas', False), ('Docker context lab', 'tcp://lab:2375', False), ('x', None, None)]))
    assert [r[0].split(' sends')[0] for r in rows] == ['DOCKER_HOST', 'Docker context lab'] and all(r[1] == 1 for r in rows), rows


if __name__ == '__main__':
    test_client_rows(); test_config_risks(); test_container_rows(); test_daemon_rows(); print('ok')
