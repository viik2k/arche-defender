# Developer package sources: where pip, uv, npm, yarn, bun, cargo, go, git, conda, gem, Maven and Composer fetch code from, and the settings that switch their
# safety checks off. AI agents run `pip install` and `npm install` all day, so a poisoned source reaches the PC through them too.
# The OS's own repos and Flatpak remotes are in updates.py (Package sources).
import re
from .core import check, warn, item, text, files, have
from .ai import repos, tilde

DEFAULT = re.compile(r'^https://(pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|registry\.yarnpkg\.com|github\.com|'
                     r'proxy\.golang\.org|index\.crates\.io)\b')
HTTP = re.compile(r'\bhttp://(?!localhost\b|127\.0\.0\.1\b|\[::1\])([^\s/"\':]+)')
CREDS = re.compile(r'\bhttps?://[^\s/:@"\']+:[^\s/@"\']+@([^\s/"\':]+)')
TLS = 'anything on the network path (another device on your LAN, public Wi-Fi, a hostile router) can swap the code you install'
BUILDS = 'lets every package run its install scripts, which pnpm otherwise asks about: the 2025 npm worms (Shai-Hulud, the Nx hack) spread through them'
BUILDS_FIX = 'Remove it, and allow only the packages that need a build step (pnpm approve-builds)'
RULES = {   # kind: (pattern, what it means, fix); a match on a line is a warning
    'pip': ((r'^\s*(?:--)?extra[-_]index[-_]url\b', 'adds a second package index: pip takes the newest version from either one, so a public '
             'package that copies the name of a private one gets installed instead (dependency confusion)',
             'Use one index-url that mirrors PyPI, or uv (it stops at the first index that has the package)'),
            (r'^\s*(?:--)?trusted[-_]host\b', f'turns off TLS checks for a package index: {TLS}', 'Remove trusted-host and fix the certificate')),
    'uv': ((r'index-strategy\s*=\s*["\']unsafe-', 'lets uv mix versions from several indexes (dependency confusion)',
            'Remove index-strategy: the default, first-index, is safe'),
           (r'allow-insecure-host\s*=', f'turns off TLS checks for a package index: {TLS}', 'Remove allow-insecure-host')),
    'npm': ((r'^\s*strict-ssl\s*=\s*false', f'turns off TLS checks for the npm registry: {TLS}', 'Remove strict-ssl=false'),
            (r'^\s*(script-shell|node-options)\s*=\s*\S', 'changes what every npm script runs with (script-shell, or node-options '
             'such as --require that loads a file into each Node process npm starts)', 'Remove that line unless you put it there'),
            (r'^\s*dangerously-allow-all-builds\s*=\s*true', BUILDS, BUILDS_FIX)),
    'pnpm': ((r'^\s*dangerouslyAllowAllBuilds:\s*true', BUILDS, BUILDS_FIX),),
    'yarn': ((r'enableStrictSsl:\s*false|^\s*strict-ssl\s+false', f'turns off TLS checks for the registry: {TLS}', 'Remove that setting'),
             (r'unsafeHttpWhitelist:', f'lets yarn fetch packages over plain HTTP: {TLS}', 'Remove unsafeHttpWhitelist')),
    'go': ((r'^\s*GOINSECURE=\S', f'fetches Go modules without TLS checks: {TLS}', 'go env -u GOINSECURE'),
           (r'^\s*GOSUMDB=off|^\s*GOFLAGS=.*-insecure', 'turns off the Go checksum database, which catches a module that changed under its version',
            'go env -u GOSUMDB GOFLAGS')),
    'git': ((r'^\s*sslverify\s*=\s*(false|no|off|0)\b', f'makes Git skip TLS checks: {TLS}', 'git config --global --unset http.sslVerify'),
            (r'^\s*\[credential\s+"http://', 'sends a Git password or token over plain HTTP: anything on the network path can read it '
             'and push code as you', 'Put that Git server behind https (Forgejo and Gitea work behind a reverse proxy with a certificate)')),
    'conda': ((r'^\s*ssl_verify\s*:\s*(false|no|0)\b', f'turns off TLS checks for conda channels: {TLS}', 'conda config --remove-key ssl_verify'),),
    'composer': ((r'"secure-http"\s*:\s*false', f'lets Composer fetch packages over plain HTTP: {TLS}', 'Remove "secure-http": false'),),
    'cargo': (), 'bun': (), 'gem': (), 'maven': ()}   # these last ones only for sources over plain HTTP
USER = {'pip': ('/etc/pip.conf', '/etc/xdg/pip/pip.conf', '~/.config/pip/pip.conf', '~/.pip/pip.conf'),
        'uv': ('/etc/uv/uv.toml', '~/.config/uv/uv.toml'), 'npm': ('/etc/npmrc', '/usr/etc/npmrc', '/usr/local/etc/npmrc', '~/.npmrc'),
        'yarn': ('~/.yarnrc.yml', '~/.yarnrc'), 'bun': ('~/.bunfig.toml',), 'cargo': ('~/.cargo/config.toml', '~/.cargo/config'),
        'go': ('~/.config/go/env',), 'git': ('/etc/gitconfig', '~/.gitconfig', '~/.config/git/config'),
        'conda': ('/etc/conda/.condarc', '/opt/conda/.condarc', '~/.condarc', '~/.conda/.condarc', '~/.config/conda/condarc'),
        'gem': ('/etc/gemrc', '~/.gemrc'), 'maven': ('~/.m2/settings.xml',), 'composer': ('~/.config/composer/config.json', '~/.composer/config.json')}
# A cloned repo's own files: `npm install` or `pip install -r` inside it follows them, whoever wrote them.
PROJECT = {'pip': ('requirements*.txt',), 'uv': ('uv.toml', 'pyproject.toml'), 'npm': ('.npmrc',), 'yarn': ('.yarnrc.yml', '.yarnrc'),
           'bun': ('bunfig.toml',), 'cargo': ('.cargo/config.toml', '.cargo/config'), 'pnpm': ('pnpm-workspace.yaml',)}


def config_rows(kind, where, t, project=False):
    """Rows for one config file's text."""
    if where.endswith('pyproject.toml'): t = '\n'.join(re.findall(r'^\[\[?tool\.uv\b[^\n]*\n(?:(?!\[)[^\n]*\n?)*', t, re.M))   # not [project.urls]
    if kind == 'maven': t = '\n'.join(re.findall(r'<url>[^<]*</url>', re.sub(r'<!--.*?-->', '', t, flags=re.S)))   # not xmlns or the template's comments
    keys = 'index[-_]url|registry|npmRegistryServer|GOPROXY|index|replace-with' + ('|url' if kind == 'uv' else '')   # uv: [[index]] url =
    for line in (re.sub(r'\s+#.*', '', l) for l in t.splitlines()):   # requirements.txt and TOML allow a comment after the value
        if re.match(r'\s*([#;]|(https?[-_.]?)?proxy\b)', line, re.I): continue   # an http:// proxy still carries https end to end
        hit, h = False, HTTP.search(line)
        for pat, what, fix in RULES[kind]:
            if re.search(pat, line, re.I): hit = True; yield warn(f'{where}{f" ({h[1]})" if h else ""} {what}', fix)
        if not hit and (m := h): yield warn(f'{where} fetches code over plain HTTP from {m[1]}: {TLS}', 'Use https:// for that source')
        if project and (m := CREDS.search(line) or re.search(r'_(authToken|auth|password)\s*=\s*(?!\$\{)\S', line)):
            yield warn(f'{where} has a password or token in plain text{" for " + m[1] if m.re is CREDS else ""}: it gets committed and pushed',
                       'Move it to your user config or an environment variable (${NPM_TOKEN}), and rotate it if the repo was ever pushed')
        for u in re.findall(rf'(?:^|[\s:-])(?:{keys})\s*[=:\s]\s*["\']?([^\s"\',]+)', line, re.I):
            if not DEFAULT.match(u) and u not in ('direct', 'off', 'true', 'false'):
                yield item(f'{where}: {kind} gets packages from {u.split("@")[-1]}')


def scripts_rows(npmrc):
    """npm runs every package's install scripts unless ignore-scripts is set in an npmrc."""
    if not re.search(r'^\s*ignore-scripts\s*=\s*true\b', npmrc, re.M | re.I):
        yield item('npm runs the install scripts of every package it installs and of all their dependencies: the 2025 npm worms '
                   '(Shai-Hulud, the Nx hack) spread that way, from one hijacked package to every PC that installed it',
                   'npm config set ignore-scripts true (then npm rebuild <package> for one that needs its build step), or use pnpm, which asks first')


@check('Developer package sources', 'Updates')
def devsources():
    """Where pip, uv, npm, yarn, bun, cargo, go, git, conda, gem, Maven and Composer get code from, and settings that turn their TLS or checksum checks off."""
    for kind, pats in USER.items():
        for f in files(*pats): yield from config_rows(kind, tilde(f), text(f))
    for r in repos():
        for kind, pats in PROJECT.items():
            for f in files(*(f'{r}/{p}' for p in pats)): yield from config_rows(kind, tilde(f), text(f), project=True)
    if have('npm'): yield from scripts_rows('\n'.join(map(text, files(*USER['npm']))))
