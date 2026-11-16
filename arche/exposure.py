# Network exposure: which listening services the firewall actually lets other machines reach, container ports
# Docker publishes around firewalld, and port forwards the router opened through UPnP.
# Also the router's identity, and another device claiming its hardware address (ARP spoofing).
# Tunnels that let the internet in past both: Tailscale Funnel and friends, ngrok, Cloudflare Tunnel, ssh -R.
# What listens at all is persistence.py's 'Network listeners'; the zones themselves are hardening.py's 'Firewall rules'.
import ipaddress, json, os, re, socket, time, urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from .core import check, warn, item, sh, have, text, files
from .hardening import INFRA_IF, argv

RISKY = {21: 'FTP', 23: 'Telnet', 139: 'Windows file sharing (SMB)', 445: 'Windows file sharing (SMB)',
         2375: 'Docker API without TLS (root on this PC for anyone who connects)', 3306: 'MySQL', 3389: 'Remote desktop (RDP)',
         5432: 'PostgreSQL', 5900: 'VNC', 5901: 'VNC', 6379: 'Redis', 8888: 'Jupyter', 9200: 'Elasticsearch',
         11211: 'memcached', 27017: 'MongoDB'}


def listening(ss):
    """(proto, port, program) for each socket bound beyond loopback, from `ss -tulnpH`."""
    seen = set()
    for l in ss.splitlines():
        f = l.split()
        if len(f) < 5 or not (m := re.match(r'^\[?(.*?)\]?(?:%(\S+))?:(\d+)$', f[4])): continue
        host, iface, port = m[1], m[2], int(m[3])
        if iface and INFRA_IF.match(iface): continue
        try:
            ip = ipaddress.ip_address(host) if host != '*' else None
            if ip and (ip.is_loopback or ip.is_multicast): continue
        except ValueError: continue
        if port >= 32768 and port not in RISKY: continue   # ponytail: ephemeral ports change every start, so they would always look new
        p = re.search(r'\(\("([^"]+)"', l)
        if not p:
            try: p = [None, f'{socket.getservbyport(port, f[0])} (system service)']
            except OSError: p = [None, 'a system service']
        if (f[0], port) not in seen: seen.add((f[0], port)); yield f[0], port, p[1]


def port_specs(specs):
    """'22/tcp 1025-65535/udp' -> [('tcp', 22, 22), ('udp', 1025, 65535)]"""
    return [(pr, int(lo), int(hi or lo)) for lo, hi, pr in re.findall(r'(\d+)(?:-(\d+))?/(\w+)', specs)]


FW_SERVICES = ('/etc/firewalld/services', '/usr/lib/firewalld/services')


def service_ports(s, depth=0):
    """A firewalld service's ports and those of the services it includes, from its XML (/etc overrides /usr/lib):
    one firewall-cmd per service took a second."""
    for d in FW_SERVICES:
        try: root = ET.parse(f'{d}/{s}.xml').getroot()
        except (OSError, ET.ParseError): continue
        return ' '.join([f'{e.get("port")}/{e.get("protocol")}' for e in root.iter('port')] +
                        [service_ports(e.get('service'), depth + 1) for e in root.iter('include') if depth < 5])
    return ' '.join(re.findall(r'^\s+ports: (.*)$', sh('firewall-cmd', f'--info-service={s}'), re.M))


def firewalld_open():
    """Ports firewalld lets in on real network interfaces, or None when a zone accepts everything."""
    rules = []
    for zone, ifs in re.findall(r'^(\S+)[^\n]*\n\s+interfaces: (.*)$', sh('firewall-cmd', '--get-active-zones'), re.M):
        if all(INFRA_IF.match(i) for i in ifs.split()): continue
        conf = dict(re.findall(r'^\s+([\w-]+): ?(.*)$', sh('firewall-cmd', f'--zone={zone}', '--list-all'), re.M))
        if conf.get('target') == 'ACCEPT': return None
        rules += port_specs(conf.get('ports', ''))
        for s in conf.get('services', '').split():
            rules += port_specs(service_ports(s))
    return rules


def exposed_rows(listeners, rules):
    """rules None = nothing is filtered (no firewall, or a zone that accepts all)."""
    for proto, port, prog in listeners:
        if rules is not None and not any(p == proto and lo <= port <= hi for p, lo, hi in rules): continue
        if port in RISKY:
            yield warn(f'{RISKY[port]} ({prog}) on {proto} port {port} is reachable from your network',
                       fix='Bind it to 127.0.0.1 in its settings, or close the port in the firewall, unless other machines must use it.')
        else: yield item(f'Reachable from your network: {prog} on {proto} port {port}')


def docker_rows(ps):
    """Published container ports from `docker ps --format '{{.Names}}\t{{.Ports}}'`."""
    for l in ps.splitlines():
        name, _, ports = l.partition('\t')
        for hp, cp in sorted(set(re.findall(r'(?:0\.0\.0\.0|\[::\]|::):(\d+(?:-\d+)?)->(\d+(?:-\d+)?/\w+)', ports))):
            yield warn(f'Container {name} publishes port {hp} ({cp}) to your whole network: Docker bypasses firewalld',
                       fix=f'Publish it on this PC only (-p 127.0.0.1:{hp}:{cp.split("/")[0]}) unless other machines need it.')


@check('Exposed services', 'Network')
def exposed():
    """Listening programs the firewall lets other machines reach, and container ports Docker opens around the firewall."""
    active = lambda u: sh('systemctl', 'is-active', u).strip() == 'active'
    if active('firewalld'): rules = firewalld_open()
    elif active('ufw') or active('nftables'): rules = []   # ponytail: their rules need root to read; assume default-deny
    else: rules = None
    yield from exposed_rows(listening(sh('ss', '-tulnpH')), rules)
    if have('docker'): yield from docker_rows(sh('docker', 'ps', '--format', '{{.Names}}\t{{.Ports}}', timeout=10))


SSDP = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\n'
        b'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n')
WAN = re.compile(r'urn:schemas-upnp-org:service:WAN(IP|PPP)Connection:\d')


def igd_locations(wait=3):
    """Description URLs of UPnP internet gateways on the LAN; only URLs pointing at the device that answered."""
    # ponytail: replies to a multicast query are not 'established' to conntrack, so a zone without high UDP ports open
    # (firewalld 'public') drops them and this finds nothing; binding a port and opening it would need root.
    s, out, end = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), set(), time.time() + wait
    try:
        s.sendto(SSDP, ('239.255.255.250', 1900))
        while (left := end - time.time()) > 0:
            s.settimeout(left)
            data, (src, _) = s.recvfrom(4096)
            m = re.search(rb'^location:\s*(\S+)', data, re.I | re.M)
            u = urllib.parse.urlsplit(m[1].decode('latin-1')) if m else None
            if u and u.scheme == 'http' and u.hostname == src and ipaddress.ip_address(src).is_private: out.add(u.geturl())
    except OSError: pass   # the timeout ends the wait
    finally: s.close()
    return out


def fetch(url, body=None, action=None):
    h = {'User-Agent': 'arche-defender'} | ({'Content-Type': 'text/xml; charset="utf-8"', 'SOAPAction': f'"{action}"'} if action else {})
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=h), timeout=4) as r: return r.read(1 << 20)


def wan_services(xml, base):
    """(serviceType, control URL) of the WAN connection services in an IGD description, on the same host only."""
    for svc in ET.fromstring(xml).iter():
        if not svc.tag.endswith('service'): continue
        f = {c.tag.split('}')[-1]: (c.text or '').strip() for c in svc}
        url = urllib.parse.urljoin(base, f.get('controlURL', ''))
        if WAN.fullmatch(f.get('serviceType', '')) and urllib.parse.urlsplit(url).hostname == urllib.parse.urlsplit(base).hostname:
            yield f['serviceType'], url


def mappings(stype, control, limit=128):
    for i in range(limit):
        body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:GetGenericPortMappingEntry xmlns:u="{stype}"><NewPortMappingIndex>{i}</NewPortMappingIndex>'
                '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>').encode()
        try: r = ET.fromstring(fetch(control, body, f'{stype}#GetGenericPortMappingEntry'))
        except (OSError, ET.ParseError): return   # HTTP 500 (SpecifiedArrayIndexInvalid) marks the end of the list
        yield {e.tag.split('}')[-1]: (e.text or '').strip() for e in r.iter()}


def mapping_rows(router, maps, mine):
    yield item(f'Router {router} has UPnP on: programs on your network can open ports to the internet without asking',
               fix='Turn UPnP off in the router admin page unless a game console or app needs it.')
    for m in maps:
        if m.get('NewEnabled', '1') == '0': continue
        what = f"{m.get('NewProtocol', '?')} port {m.get('NewExternalPort', '?')} to {m.get('NewInternalClient', '?')}:{m.get('NewInternalPort', '?')}" + \
               (f" ({m['NewPortMappingDescription'][:60]})" if m.get('NewPortMappingDescription') else '')
        if m.get('NewInternalClient') in mine:
            yield warn(f'The router forwards {what} from the internet to this PC',
                       fix='Anything on the internet can reach that port. Remove the forward in the router unless you know which program asked for it.')
        else: yield item(f'The router forwards {what} from the internet')


@check('Router port forwards (UPnP)', 'Network', slow=True)
def upnp():
    """Asks the router over UPnP which ports it forwards from the internet, and to which device."""
    mine = set(re.findall(r'inet6? ([^/ ]+)', sh('ip', '-o', 'addr')))
    for loc in igd_locations():
        try: svcs = list(wan_services(fetch(loc), loc))
        except (OSError, ET.ParseError): continue
        yield from mapping_rows(urllib.parse.urlsplit(loc).hostname, (m for st, url in svcs for m in mappings(st, url)), mine)


def maker(mac, db='/usr/share/hwdata/oui.txt'):
    """Maker of a network card from its MAC prefix (hwdata's copy of the IEEE list)."""
    if int(mac[:2], 16) & 2: return 'randomised or virtual address'
    m = re.search(rf'^{re.escape(mac[:8].replace(":", "-").upper())}\s+\(hex\)\s+(.+)$', text(db), re.M)
    return m[1].strip() if m else 'unknown maker'


def gateway_rows(gw, neigh):
    """neigh: IPv4 -> MAC from `ip -4 neigh`. Another IP answering with the router's MAC is the ARP-spoofing signature."""
    mac = neigh.get(gw)
    if not mac: return
    twins = sorted(ip for ip, m in neigh.items() if m == mac and ip != gw)
    if twins: yield warn(f'{", ".join(twins)} answers with the same hardware address as your router {gw} ({mac}): possible ARP spoofing',
                         fix='Someone on your network may be intercepting your traffic. Unplug unknown devices, reboot the router, '
                             'and check again; if it persists on a network you trust, look up that address in the router\'s client list.')
    yield item(f'Router {gw} is {mac} ({maker(mac)})', fix='If this changes without a new router, another device may be impersonating it.')


@check('Local network', 'Network')
def local():
    neigh = {ip: mac.lower() for ip, mac in re.findall(r'^(\S+) dev \S+ lladdr (\S+)', sh('ip', '-4', 'neigh', 'show'), re.M)}
    for gw in dict.fromkeys(re.findall(r'^default via (\S+)', sh('ip', '-4', 'route', 'show', 'default'), re.M)):
        yield from gateway_rows(gw, neigh)


# Programs whose job is to publish a port on this PC to the internet; attackers use the same ones to keep a way in.
TUNNELS = {'ngrok': 'ngrok', 'cloudflared': 'Cloudflare Tunnel', 'frpc': 'frp', 'bore': 'bore', 'zrok': 'zrok', 'playit': 'playit.gg',
           'chisel': 'chisel', 'inlets': 'inlets', 'loophole': 'loophole', 'loclx': 'LocalXpose'}
PUBLIC_SSH = re.compile(r'(^|@)(serveo\.net|(\w+\.)?localhost\.run|(\w+\.)?pinggy\.io|srv\.us|tuns\.sh|tunnel\.pyjam\.as)$')
SSH_ARG_OPTS = 'BbcDEeFIiJLlmOoPpQRSWw'   # ssh options that take a value
TUNNEL_FIX = ('If you did not start it, this is how attackers keep a way in: kill {pid}, then look for what started it under '
              'Startup entries, Services and Scheduled tasks.')


def ssh_reverse(a):
    """The destination of an `ssh -R` command line, else None.
    ponytail: RemoteForward set in ~/.ssh/config or with -o is not seen; parse the config if that matters."""
    rev, dest, it = False, None, iter(a[1:])
    for x in it:
        if x.startswith('-') and len(x) > 1:
            i = next((i for i, c in enumerate(x[1:]) if c in SSH_ARG_OPTS), None)   # the value is the rest, or the next word
            if i is None: continue
            rev |= x[1 + i] == 'R'
            if i == len(x) - 2: next(it, None)
        elif dest is None: dest = x
        else: break   # the remote command
    return dest if rev else None


def tunnel_rows(procs):
    """procs: (pid, argv). The command line is not shown: tunnel tokens are often passed on it."""
    for pid, a in procs:
        if not a: continue
        name = os.path.basename(a[0])
        key = next((k for k in TUNNELS if name == k or name.startswith(k + '-')), None)
        if key and (key != 'cloudflared' or 'tunnel' in a):
            yield warn(f'{TUNNELS[key]} is publishing a port on this PC to the internet (process {pid}: {a[0]})', fix=TUNNEL_FIX.format(pid=pid))
        elif name == 'ssh' and (dest := ssh_reverse(a)):
            if PUBLIC_SSH.search(dest):
                yield warn(f'ssh -R is publishing a port on this PC to the internet through {dest} (process {pid})', fix=TUNNEL_FIX.format(pid=pid))
            else: yield item(f'SSH reverse tunnel (ssh -R): {dest} can reach into this PC', fix=TUNNEL_FIX.format(pid=pid))


def serve_ports(cfg, key):
    """Ports under `key` ('TCP' or 'AllowFunnel') in a Tailscale ServeConfig, foreground sessions included."""
    out = set()
    for k, v in (cfg.items() if isinstance(cfg, dict) else ()):
        if k == key and isinstance(v, dict): out |= {str(p).rsplit(':', 1)[-1] for p, on in v.items() if on}
        elif isinstance(v, dict): out |= serve_ports(v, key)
    return out


def ports(ps): return ('port ' if len(ps) == 1 else 'ports ') + ', '.join(sorted(ps, key=lambda p: (len(p), p)))


def tailscale_rows(prefs, serve):
    funnel, shared = serve_ports(serve, 'AllowFunnel'), serve_ports(serve, 'TCP')
    if funnel: yield warn(f'Tailscale Funnel publishes {ports(funnel)} on this PC to the whole internet',
                          fix='Anyone can reach it, not just your tailnet. Check with: tailscale funnel status; stop with: tailscale funnel reset')
    if shared - funnel: yield item(f'Tailscale Serve shares {ports(shared - funnel)} with your tailnet',
                                   fix='Check with: tailscale serve status; stop with: tailscale serve reset')
    if prefs.get('RunSSH'): yield item('Tailscale SSH is on: devices your tailnet policy allows can log in to this PC',
                                       fix='Turn it off with: sudo tailscale set --ssh=false')
    if prefs.get('RunWebClient'): yield item('Tailscale web client is on: its settings page is open to your tailnet on port 5252',
                                             fix='Turn it off with: sudo tailscale set --webclient=false')
    routes = prefs.get('AdvertiseRoutes') or []
    if {'0.0.0.0/0', '::/0'} & set(routes): yield item('This PC offers itself as a Tailscale exit node for your tailnet',
                                                        fix='Stop with: sudo tailscale set --advertise-exit-node=false')
    if lan := [r for r in routes if r not in ('0.0.0.0/0', '::/0')]:
        yield item(f'This PC routes your tailnet into {", ".join(lan)} (subnet router)', fix='Stop with: sudo tailscale set --advertise-routes=')
    if prefs.get('ExitNodeID') or prefs.get('ExitNodeIP'):
        yield item('Your internet traffic goes out through a Tailscale exit node', fix='That device sees where you go. Stop with: tailscale set --exit-node=')
    if shares := [d.get('Name', '?') for d in prefs.get('DriveShares') or [] if isinstance(d, dict)]:
        yield item(f'Taildrive shares {", ".join(shares)} with your tailnet', fix='Stop sharing with: tailscale drive unshare <name>')


@check('Tunnels to the internet', 'Network')
def tunnels():
    """Ways in that skip the router and the firewall: Tailscale Funnel, Serve, SSH, subnet routes and exit nodes, and running
    tunnel programs (ngrok, Cloudflare Tunnel, frp, playit.gg, ssh -R to serveo and the like)."""
    if have('tailscale'):
        try: yield from tailscale_rows(json.loads(sh('tailscale', 'debug', 'prefs', timeout=10) or '{}') or {},
                                       json.loads(sh('tailscale', 'serve', 'status', '--json', timeout=10) or '{}') or {})
        except ValueError: pass   # tailscaled is not running
    yield from tunnel_rows((d[6:], argv(d[6:])) for d in files('/proc/[0-9]*'))
