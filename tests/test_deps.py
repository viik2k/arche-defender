import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import json, shutil, tempfile, unittest
from pathlib import Path
from unittest import mock
from arche import deps
from arche.core import ALERT, WARN, INFO

NPM = {'lockfileVersion': 3, 'packages': {
    '': {'name': 'mine'}, 'packages/local': {'version': '1.0.0'},
    'node_modules/lodash': {'version': '4.17.20', 'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz'},
    'node_modules/a/node_modules/@s/b': {'version': '2.0.0', 'resolved': 'https://registry.npmjs.org/@s/b/-/b-2.0.0.tgz'},
    'node_modules/alias': {'name': 'real', 'version': '1.0.0', 'resolved': 'https://registry.npmjs.org/real/-/real-1.0.0.tgz'},
    'node_modules/private': {'version': '1.0.0', 'resolved': 'https://npm.corp.example/private-1.0.0.tgz'},
    'node_modules/linked': {'resolved': 'packages/local', 'link': True}}}
PNPM = """lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4
        version: 4.17.20

packages:

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-x}

  lodash@4.17.20:
    resolution: {integrity: sha512-y}

  mine@file:../mine:
    resolution: {directory: ../mine}

snapshots:

  notapackage@9.9.9: {}
"""
CARGO = """[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-app"
version = "0.1.0"
"""
UV = """[[package]]
name = "pillow"
version = "12.3.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mine"
version = "0.1.0"
source = { editable = "." }
"""


class Packages(unittest.TestCase):
    def setUp(self): self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)

    def parse(self, name, body):
        Path(self.d, name).write_text(body)
        return sorted(deps.packages(os.path.join(self.d, name)))

    def test_public_registries_only(self):
        self.assertEqual(self.parse('package-lock.json', json.dumps(NPM)), [('npm', '@s/b', '2.0.0'), ('npm', 'lodash', '4.17.20'), ('npm', 'real', '1.0.0')])
        self.assertEqual(self.parse('pnpm-lock.yaml', PNPM), [('npm', '@babel/core', '7.24.0'), ('npm', 'lodash', '4.17.20')])
        self.assertEqual(self.parse('Cargo.lock', CARGO), [('crates.io', 'serde', '1.0.0')])
        self.assertEqual(self.parse('uv.lock', UV), [('PyPI', 'pillow', '12.3.0')])
        self.assertEqual(self.parse('requirements.txt', 'Django==4.2.1\nrequests[socks] == 2.31.0 ; python_version>"3"\nflask>=2\n-e .\n'),
                         [('PyPI', 'Django', '4.2.1'), ('PyPI', 'requests', '2.31.0')])
        self.assertEqual(self.parse('requirements.txt', '--index-url https://pypi.corp.example/simple\nsecret==1.0\n'), [])

    def test_more_lockfiles(self):
        yarn1 = ('# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz#a"\n\n'
                 'lodash@^4:\n  version "4.17.20"\n  resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz#b"\n\n'
                 'secret@^1:\n  version "1.0.0"\n  resolved "https://npm.corp.example/secret-1.0.0.tgz"\n')
        self.assertEqual(self.parse('yarn.lock', yarn1), [('npm', '@babel/core', '7.24.0'), ('npm', 'lodash', '4.17.20')])
        berry = ('__metadata:\n  version: 8\n\n"lodash@npm:^4":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n\n'
                 '"resolve@patch:resolve@npm%3A^1#~builtin<compat/resolve>":\n  version: 1.22.1\n  resolution: "resolve@patch:resolve@npm%3A1.22.1#x"\n\n'
                 '"mine@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "mine@workspace:."\n')
        self.assertEqual(self.parse('yarn.lock', berry), [('npm', 'lodash', '4.17.20')])
        Path(self.d, '.yarnrc.yml').write_text('npmRegistryServer: "https://npm.corp.example"\n')
        self.assertEqual(self.parse('yarn.lock', berry), [])
        bun = '{\n  "lockfileVersion": 1,\n  "packages": {\n    "lodash": ["lodash@4.17.20", "", {}, "sha512-x"],\n' \
              '    "@s/b": ["@s/b@2.0.0", "", { "dependencies": {} }, "sha512-y"],\n    "corp": ["corp@1.0.0", "https://npm.corp.example/corp.tgz", {}],\n' \
              '    "mine": ["mine@workspace:packages/mine"],\n  }\n}\n'
        self.assertEqual(self.parse('bun.lock', bun), [('npm', '@s/b', '2.0.0'), ('npm', 'lodash', '4.17.20')])
        poetry = UV.replace('source = { registry = "https://pypi.org/simple" }\n', '').replace('source = { editable = "." }', '[package.source]\ntype = "legacy"\nurl = "https://pypi.corp.example/simple"')
        self.assertEqual(self.parse('poetry.lock', poetry), [('PyPI', 'pillow', '12.3.0')])
        pipfile = {'_meta': {'sources': [{'name': 'pypi', 'url': 'https://pypi.org/simple'}, {'name': 'corp', 'url': 'https://pypi.corp.example/simple'}]},
                   'default': {'requests': {'version': '==2.31.0', 'index': 'pypi'}, 'secret': {'version': '==1.0', 'index': 'corp'}, 'mine': {'path': '.'}},
                   'develop': {'pytest': {'version': '==8.0.0'}}}
        self.assertEqual(self.parse('Pipfile.lock', json.dumps(pipfile)), [('PyPI', 'pytest', '8.0.0'), ('PyPI', 'requests', '2.31.0')])
        gem = ('GIT\n  remote: https://git.corp.example/secret.git\n  specs:\n    secret (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n'
               '    nokogiri (1.15.4-x86_64-linux)\n      racc (~> 1.4)\n    rack (3.0.8)\n\nPLATFORMS\n  x86_64-linux\n')
        self.assertEqual(self.parse('Gemfile.lock', gem), [('RubyGems', 'nokogiri', '1.15.4'), ('RubyGems', 'rack', '3.0.8')])
        composer = {'packages': [{'name': 'symfony/http-kernel', 'version': 'v5.4.1', 'notification-url': 'https://packagist.org/downloads/'},
                                 {'name': 'corp/secret', 'version': '1.0.0'}], 'packages-dev': [{'name': 'phpunit/phpunit', 'version': '10.0.0', 'notification-url': 'https://packagist.org/downloads/'}]}
        self.assertEqual(self.parse('composer.lock', json.dumps(composer)), [('Packagist', 'phpunit/phpunit', '10.0.0'), ('Packagist', 'symfony/http-kernel', '5.4.1')])

    def test_lockfiles_skip_dependency_trees(self):
        for p in ('proj/package-lock.json', 'proj/node_modules/x/package-lock.json', '.hidden/Cargo.lock', 'proj/target/Cargo.lock'):
            Path(self.d, p).parent.mkdir(parents=True, exist_ok=True); Path(self.d, p).write_text('{}')
        self.assertEqual(list(deps.lockfiles(self.d)), [os.path.join(self.d, 'proj/package-lock.json')])

    def test_installed_tools(self):
        sp = Path(self.d, 'tools/mcp-x/lib/python3.12/site-packages')
        for x in ('mcp_x-1.2.0.dist-info', 'httpx-0.27.0.dist-info', 'mine-0.1.dist-info'): (sp / x).mkdir(parents=True)
        (sp / 'mine-0.1.dist-info/direct_url.json').write_text('{"url": "file:///src/mine"}')
        self.assertEqual(sorted(deps.packages(str(sp))), [('PyPI', 'httpx', '0.27.0'), ('PyPI', 'mcp_x', '1.2.0')])
        self.assertEqual(deps.tool(str(sp))[0], 'Python tool mcp-x')
        v = Path(self.d, 'claude/versions'); v.mkdir(parents=True)
        for x in ('2.1.9', '2.1.10', '2.1.10.tmp'): (v / x).write_text('')
        self.assertEqual(list(deps.packages(str(v))), [('npm', '@anthropic-ai/claude-code', '2.1.10')])
        npx = Path(self.d, '.npm/_npx/ab12/package-lock.json'); npx.parent.mkdir(parents=True)
        npx.write_text(json.dumps({'packages': {'': {'dependencies': {'mcp-remote': '^0.1'}}}}))
        self.assertEqual(deps.tool(str(npx))[0], 'npx mcp-remote')
        self.assertEqual(deps.tool('/usr/local/lib/node_modules/.package-lock.json'), ('Global npm packages in /usr/local', 'npm update -g'))
        self.assertEqual(deps.tool(f'{deps.HOME}/.local/lib/python3.14/site-packages')[0], 'Python packages installed with pip --user')


DET = {'GHSA-crit': {'sev': 'CRITICAL', 'summary': '', 'aliases': ['PYSEC-1']}, 'PYSEC-1': {'sev': '?', 'summary': '', 'aliases': ['GHSA-crit']},
       'GHSA-mod': {'sev': 'MODERATE', 'summary': '', 'aliases': []}, 'MAL-1': {'sev': '?', 'summary': '', 'aliases': []}, 'GONE': None}


class Rows(unittest.TestCase):
    def test_rows(self):
        locks = {'/p/a/uv.lock': [['PyPI', 'pillow', '1', ['GHSA-crit', 'PYSEC-1']], ['PyPI', 'x', '2', ['GHSA-mod', 'GONE']]],
                 '/p/b/package-lock.json': [['npm', 'evil', '1.0.0', ['MAL-1']], ['npm', 'y', '1', ['GHSA-mod']]],
                 '/p/c/Cargo.lock': [['crates.io', 'z', '1', ['GONE']]]}
        rows = list(deps.rows(locks, DET))
        self.assertEqual([(s, t) for t, s, _ in rows],
                         [(INFO, '/p/a/uv.lock: dependencies with critical vulnerabilities'),
                          (ALERT, '/p/b/package-lock.json pins evil 1.0.0 (npm), a known malicious package'),
                          (INFO, '/p/b/package-lock.json: dependencies with moderate vulnerabilities'),
                          (WARN, '1 of your code projects pin dependencies with critical vulnerabilities')])
        self.assertIn('pillow 1 (critical, GHSA-crit), x 2 (moderate, GHSA-mod)', rows[0][2])
        self.assertIn('uv lock --upgrade', rows[0][2])
        tools = {'/t/claude/versions': [['npm', '@anthropic-ai/claude-code', '1', ['GHSA-crit']]],
                 '/usr/lib/node_modules/.package-lock.json': [['npm', 'y', '1', ['GHSA-mod']]]}
        self.assertEqual([(s, t) for t, s, _ in deps.rows(tools, DET, set(tools))],
                         [(WARN, 'Claude Code has critical vulnerabilities'), (INFO, 'Global npm packages in /usr has moderate vulnerabilities')])


class Update(unittest.TestCase):
    def test_update_and_check(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        Path(d, 'proj').mkdir(); Path(d, 'proj/uv.lock').write_text(UV)
        Path(d, 'claude/versions').mkdir(parents=True); Path(d, 'claude/versions/2.0.0').write_text('')

        def osv(path, body=None):
            if path == '/querybatch': return {'results': [{'vulns': [{'id': 'GHSA-crit'}]} for _ in body['queries']]}
            return {'database_specific': {'severity': 'CRITICAL'}, 'summary': 's'}
        with mock.patch.object(deps, 'HOME', d), mock.patch.object(deps, 'DB', Path(d, 'deps.json')), mock.patch.object(deps, 'osv', osv), \
                mock.patch.object(deps, 'TOOLS', (f'{d}/claude/versions',)):
            self.assertIn('2 packages in 2 lockfiles and tools; 2 have', deps.update())
            self.assertEqual([s for _, s, _ in deps.dependencies()], [INFO, WARN, WARN])
            os.utime(Path(d, 'proj/uv.lock'), (1, 1))   # edited since the check: wait for the next deps-update
            self.assertEqual([t for t, _, _ in deps.dependencies()], ['Claude Code has critical vulnerabilities'])
            with mock.patch.object(deps, 'osv', side_effect=OSError):
                self.assertIn('Could not reach', deps.update())


if __name__ == '__main__': unittest.main()
