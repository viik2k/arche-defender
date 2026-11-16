# Containers: what a Docker container can do to the host (privileged, the Docker socket or / mounted, host PID, extra
# capabilities, confinement off), a daemon that listens on the network without TLS, and new containers (cryptojacking crews
# start theirs through exposed Docker APIs and set them to restart forever). Published ports are in exposure.py.
import json, os, re, stat
from .core import check, alert, warn, item, sh, have, text, jsonf, files, HOME

SOCKETS = {'/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock', '/run/containerd/containerd.sock'}
HOST_DIRS = {'/', '/etc', '/root', '/home', '/boot', '/dev', '/usr', '/var', HOME}
CAPS = {'ALL', 'SYS_ADMIN', 'SYS_MODULE', 'SYS_PTRACE', 'SYS_RAWIO', 'DAC_READ_SEARCH', 'BPF'}
RAW_DEV = [f'/dev/{x}' for x in ('mem', 'kmem', 'port', *[f'{p}{c}' for p in ('sd', 'vd', 'hd') for c in 'abcdefgh'], *[f'nvme{i}n1' for i in range(4)], *[f'nvme{i}' for i in range(4)])]
FIX = 'Recreate it without that (docker run/compose options), unless you set it up on purpose for a tool that needs it'


def container_rows(info):
    """Rows for `docker inspect` output: a list of containers."""
    for c in info:
        name, hc, cfg = c.get('Name', '?').lstrip('/'), c.get('HostConfig') or {}, c.get('Config') or {}
        img = cfg.get('Image', '?')
        keeps = (hc.get('RestartPolicy') or {}).get('Name') in ('always', 'unless-stopped')
        yield item(f'Container {name} ({img})' + (', restarts by itself' if keeps else ''))
        bad = ['runs privileged (root on this PC)'] if hc.get('Privileged') else []
        for m in c.get('Mounts') or []:
            src = (m.get('Source') or '').rstrip('/') or '/'
            if src in SOCKETS: bad.append(f'can drive the container engine through {src} (root on this PC)')
            elif src in HOST_DIRS and m.get('RW', True): bad.append(f'can write to {src.replace(HOME, "~")} on this PC')
        if hc.get('PidMode') == 'host': bad.append('sees and can signal every process on this PC')
        if caps := sorted({x.upper().removeprefix('CAP_') for x in hc.get('CapAdd') or []} & CAPS): bad.append('has ' + ', '.join(caps))
        if off := [s for s in hc.get('SecurityOpt') or [] if re.search(r'unconfined|label[=:]disable', s)]: bad.append('runs with ' + ', '.join(off))
        if raw := sorted({d.get('PathOnHost', '') for d in hc.get('Devices') or []} & set(RAW_DEV)): bad.append('gets the raw device ' + ', '.join(raw))
        if bad: yield warn(f'Container {name} ({img}) ' + '; '.join(bad), FIX)


def daemon_rows(cfg, unit_args, sock_mode):
    """The Docker daemon's own settings: daemon.json, -H flags in its systemd unit, and the socket's permissions."""
    tls = cfg.get('tlsverify') or '--tlsverify' in unit_args
    for h in (cfg.get('hosts') or []) + re.findall(r'(?:-H|--host)[=\s]+(tcp://\S+)', unit_args):
        if h.startswith('tcp://') and not tls:
            yield alert(f'Docker accepts commands on {h} without TLS: anyone who reaches that port is root on this PC',
                        'Remove the tcp:// host (daemon.json or the docker.service override), or set tlsverify with client certificates')
    if cfg.get('insecure-registries'):
        yield warn(f'Docker pulls images over plain HTTP from {", ".join(cfg["insecure-registries"])}: anyone on the path can swap them',
                   'Give the registry a TLS certificate and remove insecure-registries from /etc/docker/daemon.json')
    if sock_mode is not None and sock_mode & stat.S_IWOTH:
        yield alert('The Docker socket is writable by every user: any program on this PC can become root', 'sudo chmod 660 /var/run/docker.sock')


# What a compose file or dev container asks for: the same takeovers, read before you run `docker compose up` or "Reopen in Container"
RISKS = ((r'privileged["\']?\s*[:=]\s*["\']?true|--privileged\b', 'runs privileged (root on this PC)'),
         (r'/run/(docker|podman/podman|containerd/containerd)\.sock', 'can drive the container engine through its socket (root on this PC)'),
         (r'\bpid["\']?\s*[:=]\s*["\']?host\b|--pid[=\s]+host\b', 'sees and can signal every process on this PC'),
         (r'(?:^\s*-\s*|-v[=\s]+|--volume[=\s]+|source[=:]\s*)["\']?(/|/etc|/root|/home|/boot|/dev|(?:~|\$\{?HOME\}?)(?:/\.(?:ssh|aws|gnupg|kube|docker))?)(?=[:"\'\s,]|$)',
          'mounts {} from this PC'),
         (r'(/dev/(?:sd[a-h]|vd[a-h]|hd[a-h]|nvme\d(?:n1)?|mem|kmem|port))\b', 'gets the raw device {}'),
         (r'(?:apparmor|seccomp)[:=]unconfined|label[:=]disable', 'turns its confinement off'))


def config_risks(t):
    """Phrases for what a compose file, or a dev container's run options flattened to text, gives its containers on this PC."""
    out = [msg.format(*m.groups()) for rx, msg in RISKS for m in re.finditer(rx, t, re.M | re.I)]
    caps = ' '.join(re.findall(r'cap_add:\s*((?:\n\s*-\s*\S+)+|\[[^\]]*\])', t) + re.findall(r'--cap-add[=\s]+(\S+)', t))
    if c := sorted({x.upper().removeprefix('CAP_') for x in re.findall(r'[\w]+', caps)} & CAPS): out.append('adds ' + ', '.join(c))
    return list(dict.fromkeys(out))


def devcontainer_text(j):
    """A devcontainer.json's privileges as docker-run-like text, for config_risks."""
    ms = [m if isinstance(m, str) else ','.join(f'{k}={v}' for k, v in m.items()) for m in j.get('mounts') or [] if isinstance(m, (str, dict))]
    return ' '.join(['--privileged' if j.get('privileged') is True else '', *map(str, j.get('runArgs') or []),
                     *(f'--cap-add {c}' for c in j.get('capAdd') or []), *(f'--security-opt {o}' for o in j.get('securityOpt') or []), *ms])


def client_rows(hosts):
    """Where the docker command sends its commands, as (where, host, has TLS): tcp:// without TLS is root on that machine for anyone who reaches it."""
    for where, h, tls in hosts:
        if (h or '').startswith('tcp://') and not tls:
            yield warn(f'{where} sends Docker commands to {h} without TLS: that machine\'s Docker takes root-level commands from anyone who can reach it',
                       'On that machine, put the API behind TLS (tlsverify with client certificates), or use ssh://user@host instead')


@check('Containers', 'Protection')
def containers():
    """Docker containers that can take over the host, and a daemon that listens without TLS."""
    try: mode = os.stat('/var/run/docker.sock').st_mode
    except OSError: mode = None
    units = ' '.join(text(f) for f in files('/etc/systemd/system/docker.service.d/*.conf', '/etc/systemd/system/docker.service'))
    yield from daemon_rows(jsonf('/etc/docker/daemon.json'), units, mode)
    hosts = [('DOCKER_HOST', os.environ.get('DOCKER_HOST'), os.environ.get('DOCKER_TLS_VERIFY'))]
    for f in files('~/.docker/contexts/meta/*/meta.json'):   # the folder is the hash of the context name; its TLS files sit under contexts/tls/<same hash>
        j = jsonf(f)
        h = ((j.get('Endpoints') or {}).get('docker') or {})
        hosts.append((f'Docker context {j.get("Name", "?")}', h.get('Host'), os.path.isdir(f'{HOME}/.docker/contexts/tls/{os.path.basename(os.path.dirname(f))}/docker')))
    yield from client_rows(hosts)
    if not have('docker'): return   # ponytail: rootless Podman containers are left out, they cannot reach past your own user
    ids = sh('docker', 'ps', '-aq', timeout=10).split()   # stopped ones too: restart policies bring them back at boot
    if ids:
        try: yield from container_rows(json.loads(sh('docker', 'inspect', *ids, timeout=20) or '[]'))
        except ValueError: pass
