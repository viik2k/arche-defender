# Run: python3 tests/test_devsources.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.devsources import config_rows


def rows(kind, t, project=False, where='f'): return [(s, x) for x, s, _ in config_rows(kind, where, t, project)]


def test_pip():
    r = rows('pip', '[global]\nextra-index-url = https://download.pytorch.org/whl/cu121\ntrusted-host = pypi.internal\n'
                    'proxy = http://proxy.lan:3128\n# index-url = http://old.lan/simple\n')
    assert [s for s, _ in r] == [1, 0, 1], r   # dependency confusion, the extra index listed, TLS off; the proxy and comment are fine
    assert 'download.pytorch.org/whl/cu121' in r[1][1]


def test_requirements_from_a_cloned_repo():
    r = rows('pip', '--extra-index-url https://bob:s3cret@pkgs.example.com/simple\nrequests==2.32.3\n', project=True)
    assert [s for s, _ in r] == [1, 1, 0], r
    assert not any('s3cret' in x or 'bob' in x for _, x in r) and 'pkgs.example.com' in r[1][1], r
    assert rows('pip', 'flask==3.0.0  # http://example.com changelog\n', project=True) == []
    assert [s for s, _ in rows('pip', 'mylib @ http://files.lan/mylib-1.0.tar.gz\n', project=True)] == [1]


def test_npm_yarn_go_git():
    assert [s for s, _ in rows('npm', 'strict-ssl=false\nregistry=http://npm.lan/\n')] == [1, 1, 0]
    assert rows('npm', '@acme:registry=https://npm.pkg.github.com\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n', True) == \
        [(0, 'f: npm gets packages from https://npm.pkg.github.com')]
    assert [s for s, _ in rows('npm', '//npm.pkg.github.com/:_authToken=ghp_abc123\n', True)] == [1]
    assert [s for s, _ in rows('npm', '//npm.pkg.github.com/:_authToken=ghp_abc123\n')] == []   # your own ~/.npmrc: hardening checks its mode
    assert [s for s, _ in rows('yarn', 'enableStrictSsl: false\nhttpProxy: "http://proxy.lan:3128"\n')] == [1]
    assert [s for s, _ in rows('go', 'GOINSECURE=example.com\nGOSUMDB=off\nGOPROXY=http://goproxy.lan\n')] == [1, 1, 1, 0]
    assert [s for s, _ in rows('git', '[http]\n\tsslVerify = false\n\tproxy = http://proxy.lan:3128\n')] == [1]
    r = rows('git', '[credential "http://192.168.4.101:3000"]\n\thelper = store\n')
    assert [s for s, _ in r] == [1] and 'password' in r[0][1], r   # one row: the password over HTTP, not also "fetches code"
    assert rows('git', '[user]\n\tname = x\n[url "https://github.com/"]\n\tinsteadOf = git@github.com:\n') == []


def test_uv_and_pyproject():
    assert [s for s, _ in rows('uv', 'index-strategy = "unsafe-best-match"\n[[index]]\nurl = "https://download.pytorch.org/whl/cpu"\n')] == [1, 0]
    py = ('[project]\nname = "x"\n[project.urls]\nHomepage = "http://example.com"\n[[tool.uv.index]]\nname = "torch"\n'
          'url = "https://download.pytorch.org/whl/cpu"\n[tool.ruff]\nline-length = 120\n')
    assert rows('uv', py, True, 'repo/pyproject.toml') == [(0, 'repo/pyproject.toml: uv gets packages from https://download.pytorch.org/whl/cpu')]
    assert rows('cargo', '[source.crates-io]\nreplace-with = "vendored-sources"\n') == [(0, 'f: cargo gets packages from vendored-sources')]


if __name__ == '__main__':
    test_pip(); test_requirements_from_a_cloned_repo(); test_npm_yarn_go_git(); test_uv_and_pyproject(); print('ok')
