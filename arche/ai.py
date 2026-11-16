# AI agents: the newest way onto a PC is through the tools you let act for you. Inventories Claude Code, Codex, Gemini,
# Cursor, VS Code, Windsurf and friends (plugins, skills, hooks, MCP servers, editor extensions), scans their files for
# hidden instructions and malicious commands, flags settings that let an agent act without asking, finds plaintext API
# keys (never printing them), local model servers open to the network, and pickle model files that run code when loaded.
import io, json, os, pickletools, re, zipfile
from struct import error as struct_error
from pathlib import Path
from .hardening import argv
from .core import HOME, ALERT, WARN, alert, warn, item, ver, sh, text, files, jsonf, check

try: from .malware import match as _match
except ImportError: _match = None
try: from .intel import domain_hit
except ImportError: domain_hit = None

FAM = 'AI agents'
# (name, severity, regex, hints): a rule only runs on text containing one of its lowercase hints, which keeps a 16 MB plugin cache fast.
# Quoted phrases ("ignore previous instructions") are skipped: that is a skill warning about injection, not doing it.
Q = r'(?<![\"\'\u201c\u2018`])'
AI_RULES = [(n, s, re.compile(p, re.I), h) for n, s, p, h in (
    ('invisible Unicode tag characters (hidden instructions)', ALERT, r'[\U000E0000-\U000E007F]{3,}', None),
    ('invisible code: a run of Unicode variation selectors (the GlassWorm trick)', ALERT, r'[\uFE00-\uFE0F\U000E0100-\U000E01EF]{8,}', None),
    ('bidirectional text override characters', WARN, r'[\u202A-\u202E\u2066-\u2069]', None),
    ('tells the agent to keep things from you', WARN,
     Q + r"\b((do not|don't|never)\s+(tell|inform|notify|alert|let)\s+the user\s+(know|about|that|what|you)\b|"
     r"(do not|don't|never)\s+mention\b[^\n]{0,120}\bthe user|without (telling|notifying|informing|alerting) the user|without the user(\'s)? (knowing|knowledge|noticing)|"
     r"(hide|conceal|keep) (this|it|these|that) (secret |hidden )?from the user)", ('the user',)),
    ('prompt-injection phrasing', WARN, Q + r'\b(ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|rules)|'
                                        r'disregard (your|the|all) (instructions|guidelines|system prompt))', ('ignore', 'disregard')),
    ('reads SSH private keys', WARN, r'\b(cat|cp|scp|base64|curl|read\w*|load\w*|send\w*|upload\w*|include|attach|pass)\b[^\n]{0,60}'
                                     r'\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)', ('.ssh/id_',)),
    # Mentioning the file is fine (a note, an existence check); reading, copying or sending it is not.
    ('reads AI login credentials', ALERT, r'(?:\b(?:cat|less|more|head|tail|strings|cp|scp|rsync|tar|zip|base64|xxd|curl|wget|nc|jq|open|'
     r'read\w*|load\w*|upload\w*|send\w*|exfil\w*|steal|grab|copy|print|dump|find|search|collect|harvest)\b[^\n]{0,60})'
     r'(?:\.claude/\.credentials\.json|\.codex/auth\.json|gcloud/application_default_credentials)',
     ('credentials.json', 'auth.json', 'application_default')),
    ('sends data to a paste, tunnel or request-capture site', WARN,
     r'webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|pastebin\.com/api|transfer\.sh|'
     r'interact\.sh|\boast\.(fun|me|pro|live|site|online)|burpcollaborator',
     ('webhook.site', 'requestbin', 'pipedream', 'ngrok', 'trycloudflare', 'pastebin', 'transfer.sh', 'interact.sh', 'oast.', 'burpcollab')),
    ('rewrites agent permissions or hooks', WARN, r'(>>?|\btee\b|write_text|writeFile\w*\(|json\.dump)[^\n]{0,80}\.claude/settings(\.local)?\.json',
     ('.claude/settings',)),
)]
SECRET = re.compile(r'sk-ant-[\w-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{32,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{30,}|xox[abpr]-[\w-]{10,}|'
                    r'AIza[\w-]{30,}|hf_[A-Za-z0-9]{30,}|glpat-[\w-]{20,}|(?<=Bearer )[\w.~+/=-]{16,}|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}')
SECRET_KIND = (('sk-ant-', 'Anthropic key'), ('sk-', 'OpenAI-style key'), ('gh', 'GitHub token'), ('github_pat_', 'GitHub token'),
               ('xox', 'Slack token'), ('AIza', 'Google key'), ('hf_', 'Hugging Face token'), ('glpat-', 'GitLab token'), ('eyJ', 'JWT'))
SCAN_EXT = {'.md', '.sh', '.bash', '.py', '.js', '.mjs', '.cjs', '.ts', '.json', '.ps1', '.toml', '.yaml', '.yml', '.txt', ''}
PRUNE = {'node_modules', '.git', '.cache', '.local', '.var', '.steam', 'Steam', '.cargo', '.rustup', 'go', '.npm', '.nvm',
         'venv', '.venv', 'site-packages', 'target', 'dist', 'build', '.wine', 'Games', 'snap'}
AI_PORTS = {11434: 'Ollama', 1234: 'LM Studio', 8188: 'ComfyUI', 7860: 'Gradio / Stable Diffusion WebUI', 7861: 'Gradio',
            5001: 'KoboldCpp', 8080: 'llama.cpp / Open WebUI', 3000: 'Open WebUI', 9090: 'InvokeAI', 8000: 'vLLM'}
AI_PROC = re.compile(r'ollama|llama|lms|lm-studio|comfy|python|koboldcpp|vllm|invokeai|open-webui|uvicorn|node', re.I)
EDITORS = (('VS Code', '~/.vscode/extensions'), ('VS Code (Flatpak)', '~/.var/app/com.visualstudio.code/data/vscode/extensions'),
           ('VS Code Insiders', '~/.vscode-insiders/extensions'), ('VSCodium', '~/.vscode-oss/extensions'),
           ('VSCodium (Flatpak)', '~/.var/app/com.vscodium.codium/data/codium/extensions'), ('Cursor', '~/.cursor/extensions'),
           ('Windsurf', '~/.windsurf/extensions'), ('Kiro', '~/.kiro/extensions'), ('Trae', '~/.trae/extensions'))
EDITOR_SETTINGS = ('~/.config/Code/User/settings.json', '~/.config/Code - Insiders/User/settings.json', '~/.config/VSCodium/User/settings.json',
                   '~/.config/Cursor/User/settings.json', '~/.config/Windsurf/User/settings.json', '~/.config/Kiro/User/settings.json',
                   '~/.var/app/com.visualstudio.code/config/Code/User/settings.json')
# Every config file an agent or editor keeps MCP servers in (JSON; Codex is TOML and handled apart).
MCP_FILES = ('~/.claude.json', '~/.config/Claude/claude_desktop_config.json', '~/.cursor/mcp.json', '~/.codeium/windsurf/mcp_config.json',
             '~/.gemini/settings.json', '~/.config/Code/User/mcp.json', '~/.config/Code/User/settings.json', '~/.config/Cursor/User/settings.json',
             '~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
             '~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json', '~/.continue/config.json',
             '~/.config/opencode/opencode.json', '~/.kiro/settings/mcp.json', '~/.aws/amazonq/mcp.json', '~/.lmstudio/mcp.json',
             '~/.config/zed/settings.json')
MEMORY_FILES = ('~/.claude/CLAUDE.md', '~/.claude/memory/*.md', '~/.claude/projects/*/memory/*.md', '~/.codex/AGENTS.md', '~/.gemini/GEMINI.md',
                '~/.config/opencode/AGENTS.md', '~/.qwen/QWEN.md', '~/.windsurf/memories/*', '~/.codeium/windsurf/memories/*')
CLAUDE_EXT = '~/.config/Claude/Claude Extensions'
SKILL_DIRS = ('~/.claude/skills', '~/.claude/commands', '~/.claude/agents', '~/.agents/skills', '~/.codex/skills', '~/.codex/prompts',
              '~/.gemini/extensions', '~/.gemini/commands', '~/.config/opencode/agent', '~/.config/opencode/command', '~/.cursor/rules')
INSTRUCTION_FILES = ('CLAUDE.md', 'AGENTS.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.clinerules', '.github/copilot-instructions.md')


def tilde(p): return str(p).replace(HOME, '~', 1)
def redact(s): return re.sub(r'([?&][^=&\s]+=)[^&\s"]+', r'\1...', SECRET.sub('...', str(s)))


def jsonc(p):
    """JSON, tolerating the // comments and trailing commas VS Code and Zed allow."""
    t = text(p)
    try: return json.loads(t)
    except ValueError: pass
    t = re.sub(r'^\s*//.*$|/\*.*?\*/', '', t, flags=re.M | re.S)
    try: return json.loads(re.sub(r',\s*([}\]])', r'\1', t))
    except ValueError: return {}


def scan_text(t, where):
    """Rule hits in one file or command: AI rules plus the malware rules when that module is present."""
    low = t.lower()
    hits = [(n, s, m.group(0)[:80]) for n, s, rx, h in AI_RULES if (not h or any(x in low for x in h)) and (m := rx.search(t))]
    if _match: hits += _match(t)
    for n, s, snip in hits:
        snip = redact(snip.encode('unicode_escape').decode() if re.search(r'[\U000E0000-\U000E01EF\uFE00-\uFE0F‪-‮⁦-⁩]', snip) else snip)
        yield (alert if s == ALERT else warn)(f'{where}: {n}: "{snip.strip()}"', 'Read it before your agent runs it again; remove the plugin/skill if you did not expect this')


def scan_tree(root, label, limit=1 << 20):
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x not in ('node_modules', '.git') and not x.startswith(('temp_git_', '.staging', '.replaced-'))]
        for f in fs:
            p = os.path.join(d, f)
            if os.path.splitext(f)[1].lower() not in SCAN_EXT or os.path.islink(p): continue
            try:
                if os.path.getsize(p) > limit: continue
            except OSError: continue
            yield from scan_text(text(p), f'{label} {tilde(p)}')


def servers(obj, path=()):
    """Find MCP server tables anywhere in a config: {name: {command/args or url}} under mcpServers/servers/context_servers/mcp."""
    if not isinstance(obj, dict): return
    for k, v in obj.items():
        if k in ('mcpServers', 'servers', 'context_servers', 'mcp') and isinstance(v, dict):
            for name, s in v.items():
                if isinstance(s, dict) and any(x in s for x in ('command', 'url', 'serverUrl', 'httpUrl', 'args')): yield path, name, s
        elif isinstance(v, dict): yield from servers(v, path + (k,))


def describe(s):
    cmd = s.get('command', '')
    cmd = ' '.join(cmd) if isinstance(cmd, list) else cmd
    line = ' '.join(str(x) for x in [cmd, *s.get('args', [])]).strip() or s.get('url') or s.get('serverUrl') or s.get('httpUrl') or '?'
    env = sorted(s.get('env', {}) or {}) + sorted(s.get('headers', {}) or {})
    return redact(line)[:200] + (f'  (env: {", ".join(env)})' if env else '')


def judge_server(name, s, where):
    d = describe(s)
    yield item(ver(f'MCP server {name} ({where}): {d}'))
    url = str(s.get('url') or s.get('serverUrl') or s.get('httpUrl') or '')
    host = re.match(r'^\w+://([^/:?]+)', url)
    if url.startswith('http://') and host and not re.match(r'^(localhost|127\.|\[?::1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|100\.)', host[1]):
        yield warn(f'MCP server {name} ({where}) talks to {host[1]} unencrypted (http://)', 'Use the https:// endpoint')
    if host and domain_hit and (hit := domain_hit(host[1])): yield alert(f'MCP server {name} ({where}) points at a known-bad host {host[1]} ({hit})')
    cmd = ' '.join(str(x) for x in [s.get('command', ''), *s.get('args', [])])
    if re.search(r'(^|/)(tmp|dev/shm|var/tmp)/|/Downloads/', cmd): yield alert(f'MCP server {name} ({where}) runs a program from a temp/download folder: {redact(cmd)[:160]}')
    yield from scan_text(cmd, f'MCP server {name} ({where})')


def unpinned(s):
    c = [str(x) for x in [s.get('command', ''), *s.get('args', [])]]
    if not c or os.path.basename(c[0]) not in ('npx', 'bunx', 'uvx', 'pnpm', 'pipx', 'dlx'): return False
    pkgs = [a for a in c[1:] if not a.startswith('-') and a not in ('dlx', 'run', 'exec')][:1]
    return bool(pkgs) and not re.search(r'@\d|==\d|@sha256:', pkgs[0])


def secret_kinds(t):
    kinds = set()
    for m in SECRET.finditer(t):
        s = m.group(0)
        kinds.add(next((k for p, k in SECRET_KIND if s.startswith(p)), 'bearer token'))
    return sorted(kinds)


@check('AI plugins, skills and hooks', FAM)
def plugins():
    st = jsonf(f'{HOME}/.claude/settings.json')
    for k, on in (st.get('enabledPlugins') or {}).items(): yield item(f'Claude Code plugin {k} ({"enabled" if on else "disabled"})')
    for name, m in jsonf(f'{HOME}/.claude/plugins/known_marketplaces.json').items():
        src = m.get('source', {}) if isinstance(m, dict) else {}
        yield item(f'Claude Code plugin marketplace {name}: {src.get("repo") or src.get("url") or src.get("path") or "?"}')
    for root in SKILL_DIRS:
        for sk in files(f'{root}/*/SKILL.md', f'{root}/SKILL.md', f'{root}/*.md', f'{root}/*/gemini-extension.json'):
            nm = re.search(r'^name:\s*(.+)$', text(sk), re.M)
            yield item(f'Skill/command {nm[1].strip() if nm else Path(sk).parent.name} ({tilde(sk)})')
    for f in files('~/.claude/settings.json', '~/.claude/settings.local.json', '/etc/claude-code/managed-settings.json',
                   '~/.claude/plugins/cache/*/*/*/hooks/hooks.json', '~/.claude/plugins/cache/*/*/*/hooks.json'):
        where = re.sub(r'.*/plugins/cache/[^/]+/([^/]+)/.*', r'plugin \1', tilde(f))
        for ev, groups in (jsonf(f).get('hooks') or {}).items():
            for g in groups if isinstance(groups, list) else []:
                for h in g.get('hooks', []) if isinstance(g, dict) else []:
                    cmd = h.get('command') or h.get('url') or h.get('prompt') or ''
                    yield item(ver(f'Hook {ev} ({where}): {redact(cmd)[:160]}'))
                    yield from scan_text(cmd, f'Hook {ev} ({where})')
    codex = text(f'{HOME}/.codex/config.toml')
    if m := re.search(r'^notify\s*=\s*(.+)$', codex, re.M): yield item(f'Codex notify hook: {redact(m[1])[:160]}')


@check('AI skill and plugin contents', FAM)
def contents():
    for d in files('~/.claude/plugins/cache/*/*/*'):
        if '/temp_git_' not in d: yield from scan_tree(d, 'plugin')
    for root in SKILL_DIRS:
        if os.path.isdir(os.path.expanduser(root)): yield from scan_tree(os.path.expanduser(root), 'skill')
    for d in files(f'{CLAUDE_EXT}/*'): yield from scan_tree(d, 'Claude Desktop extension')
    # Agent memory and global instructions load into every session: an injection an agent was tricked into saving stays there.
    for f in files(*MEMORY_FILES): yield from scan_text(text(f), f'agent memory {tilde(f)}')


@check('AI agent permissions', FAM)
def permissions():
    for f in files('~/.claude/settings.json', '~/.claude/settings.local.json', '/etc/claude-code/managed-settings.json'):
        yield from claude_settings(jsonf(f), tilde(f))
    codex = text(f'{HOME}/.codex/config.toml')
    if re.search(r'^\s*approval_policy\s*=\s*"never"', codex, re.M):
        yield warn('Codex runs commands without asking (approval_policy = "never")', 'Use "on-request" in ~/.codex/config.toml')
    if re.search(r'^\s*sandbox_mode\s*=\s*"danger-full-access"', codex, re.M):
        yield warn('Codex sandbox is off (sandbox_mode = "danger-full-access")', 'Use "workspace-write" in ~/.codex/config.toml')
    if re.search(r'"(yolo|autoAccept)"\s*:\s*true', text(f'{HOME}/.gemini/settings.json')):
        yield warn('Gemini CLI auto-accepts tool calls', 'Turn off autoAccept/yolo in ~/.gemini/settings.json')
    for f in files(*EDITOR_SETTINGS):
        s = jsonc(f)
        if s.get('chat.tools.autoApprove') is True or s.get('chat.tools.global.autoApprove') is True:
            yield warn(f'Editor chat agent runs tools without asking ({tilde(f)})', 'Set chat.tools.global.autoApprove to false')
        if s.get('security.workspace.trust.enabled') is False:
            yield warn(f'Workspace Trust is off ({tilde(f)}): opened folders can run tasks and extensions code', 'Set security.workspace.trust.enabled to true')
        if s.get('task.allowAutomaticTasks') == 'on':
            yield warn(f'Folders can start tasks automatically when opened ({tilde(f)})', 'Set task.allowAutomaticTasks to "off"')


def run_settings(s):
    """(setting, command) for Claude Code settings that run a command, and env vars that make what it starts load code."""
    cmds = [(k, s[k]) for k in ('apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper') if isinstance(s.get(k), str)]
    if isinstance(s.get('statusLine'), dict) and s['statusLine'].get('type') == 'command': cmds.append(('statusLine', str(s['statusLine'].get('command', ''))))
    env = s.get('env') if isinstance(s.get('env'), dict) else {}
    return cmds + [(f'env {k}', str(v)) for k, v in env.items() if k in CODE_ENV]


def claude_settings(s, where):
    p = s.get('permissions') or {}
    if p.get('defaultMode') == 'bypassPermissions':
        yield warn(f'Claude Code skips all permission prompts by default ({where})', 'Remove "defaultMode": "bypassPermissions"')
    if s.get('skipDangerousModePermissionPrompt'): yield warn(f'Claude Code bypass-mode warning is turned off ({where})')
    wide = [a for a in p.get('allow', []) if a in ('Bash', 'Bash(*)', 'Bash(*:*)', 'Bash(:*)', 'Bash(sudo:*)', 'Bash(curl:*)', 'Bash(sh:*)', 'Bash(bash:*)')]
    if wide: yield warn(f'Claude Code may run {", ".join(wide)} without asking ({where})', 'Allow specific commands instead of whole shells')
    if s.get('enableAllProjectMcpServers'):
        if where.endswith('settings.local.json') and '/.claude/' in where and not where.startswith('~/.claude/'):
            yield item(f'Claude Code auto-starts every MCP server in this project\'s .mcp.json ({where})')   # you approved it here
        else: yield warn(f'Claude Code auto-starts MCP servers from .mcp.json without asking ({where}): a cloned repo can run code',
                         'Remove "enableAllProjectMcpServers" and approve servers one by one')
    for k, c in run_settings(s):
        yield item(ver(f'Claude Code {k} ({where}) runs: {redact(c)[:160]}'))
        yield from scan_text(c, f'Claude Code {k} ({where})')
    base = str((s.get('env') or {}).get('ANTHROPIC_BASE_URL', ''))
    if base and not re.match(r'^https://([\w-]+\.)*anthropic\.com', base):
        yield warn(f'Claude Code traffic goes through {redact(base)} ({where}): that host sees every prompt and key',
                   'Remove ANTHROPIC_BASE_URL unless you run that proxy yourself')


CODE_ENV = {'NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'BASH_ENV', 'ENV', 'PYTHONSTARTUP', 'PYTHONPATH', 'PERL5OPT', 'RUBYOPT',
            'GIT_SSH_COMMAND', 'GIT_EXTERNAL_DIFF', 'GIT_ASKPASS', 'SSH_ASKPASS', 'PAGER', 'EDITOR', 'PROMPT_COMMAND', 'SHELL'}


AGENT_BYPASS = re.compile(r'^(--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo|--yes-always|'
                          r'--permission-mode=bypassPermissions|--approval-mode=yolo|--sandbox=danger-full-access)$')
AGENT_NAME = re.compile(r'claude|codex|gemini|aider|opencode|goose|cursor-agent|qwen|amp|crush|cline', re.I)


@check('Running AI agents', FAM)
def running():
    # An agent started with its approvals off can do anything you can, and so can any prompt injection it reads.
    found = set()
    for pid in filter(str.isdigit, os.listdir('/proc')):
        a = argv(pid)
        prog = AGENT_NAME.search(' '.join(a[:2]))   # the agent itself, or node/python running its script
        if not prog or pid == str(os.getpid()): continue
        pairs = zip(a, a[1:] + [''])
        bad = sorted({f for x, y in pairs for f in (x, f'{x}={y}') if AGENT_BYPASS.match(f)})
        if bad: found.add((prog[0].lower(), ', '.join(bad)))
    for name, bad in sorted(found):
        yield warn(f'{name} is running with its permission checks off ({bad}): it can run any command without asking',
                   'Fine for a throwaway container or VM; on your own account, restart it without that flag')


@check('MCP servers', FAM)
def mcp():
    loose = []
    srcs = [(tilde(f), jsonc(f)) for f in files(*MCP_FILES)]
    srcs += [(re.sub(r'.*/plugins/cache/[^/]+/([^/]+)/.*', r'plugin \1', f), {'mcpServers': jsonf(f).get('mcpServers', jsonf(f))})
             for f in files('~/.claude/plugins/cache/*/*/*/.mcp.json')]
    for where, conf in srcs:
        for path, name, s in servers(conf):
            w = where + (f' > {path[-1]}' if path and path[-1] not in ('mcp',) and where.endswith('.claude.json') else '')
            yield from judge_server(name, s, tilde(w))
            if unpinned(s): loose.append(name)
    for mf in files(f'{CLAUDE_EXT}/*/manifest.json'):   # .mcpb/.dxt bundles: MCP servers that run unsandboxed
        j = jsonf(mf); cfg = (j.get('server') or {}).get('mcp_config') or {}
        yield from judge_server(j.get('display_name') or j.get('name') or Path(mf).parent.name, cfg, 'Claude Desktop extension')
    codex = text(f'{HOME}/.codex/config.toml')
    for name, body in re.findall(r'^\[mcp_servers\.([^\]]+)\]\n((?:[^\[].*\n?)*)', codex, re.M):
        cmd = re.search(r'^command\s*=\s*"([^"]*)"', body, re.M)
        args = re.findall(r'"([^"]*)"', (re.search(r'^args\s*=\s*\[(.*?)\]', body, re.M | re.S) or [''])[0] or '')
        url = re.search(r'^url\s*=\s*"([^"]*)"', body, re.M)
        s = {'command': cmd[1] if cmd else '', 'args': args, 'url': url[1] if url else ''}
        yield from judge_server(name, s, '~/.codex/config.toml')
        if unpinned(s): loose.append(name)
    if loose:
        yield warn(f'{len(loose)} MCP server(s) run whatever package version is newest (npx/uvx without a pinned version): '
                   f'{", ".join(sorted(set(loose)))}', 'Pin a version (pkg@1.2.3) so a hijacked release cannot run on your PC')


# Where npx/uvx keep the MCP servers they run, and where global AI CLIs (Claude Code, Codex, Gemini CLI) are installed.
NPM_ROOTS = ('~/.npm/_npx/*/node_modules', '~/.npm-global/lib/node_modules', '~/.nvm/versions/node/*/lib/node_modules',
             '~/.local/share/pnpm/global/*/node_modules', '~/.bun/install/global/node_modules', '/usr/lib/node_modules', '/usr/local/lib/node_modules')
PY_ENVS = ('~/.cache/uv/archive-v0/*', '~/.local/share/uv/tools/*', '~/.local/share/pipx/venvs/*')
# What npm worms left in install scripts: Shai-Hulud ran trufflehog for secrets, the Nx "s1ngularity" hack had AI CLIs hunt them.
WORM = re.compile(r'trufflehog|shai-?hulud|--dangerously-skip-permissions|--dangerously-bypass-approvals|--yolo\b|--trust-all-tools', re.I)


def install_scripts(nm):
    """(package, hook, command, package dir) for each package in a node_modules folder that runs code when installed."""
    # ponytail: top-level and @scope packages only (npm hoists nearly everything there); nested node_modules are not read
    for pj in files(f'{nm}/*/package.json', f'{nm}/@*/*/package.json'):
        meta = jsonf(pj)
        scripts = meta.get('scripts') if isinstance(meta.get('scripts'), dict) else {}
        for hook in ('preinstall', 'install', 'postinstall'):
            if isinstance(scripts.get(hook), str): yield meta.get('name') or Path(pj).parent.name, hook, scripts[hook], os.path.dirname(pj)


@check('Agent tool packages', FAM)
def packages():
    # The install scripts already ran, so this is a post-mortem: did a hijacked release of an MCP server or AI CLI run something?
    for root in NPM_ROOTS:
        for nm in files(root):
            where = 'npx' if '/_npx/' in nm else 'npm global'
            if where == 'npx':   # the MCP server itself (not its dependencies): tool descriptions are where tool poisoning hides
                for dep in jsonf(os.path.join(os.path.dirname(nm), 'package.json')).get('dependencies') or {}:
                    if os.path.isdir(os.path.join(nm, dep)): yield from scan_tree(os.path.join(nm, dep), f'MCP server package {dep}', 8 << 20)
            for name, hook, cmd, d in install_scripts(nm):
                yield item(ver(f'{where} package {name} runs on install ({hook}): {redact(cmd)[:120]}'))
                body = cmd + '\n'.join(text(os.path.join(d, f)) for f in re.findall(r'\bnode\s+([\w./-]+\.c?m?js)\b', cmd)
                                       if os.path.isfile(os.path.join(d, f)) and os.path.getsize(os.path.join(d, f)) < 16 << 20)
                if m := WORM.search(body):
                    yield alert(f'{where} package {name}: its {hook} script mentions {m[0]}, the mark of an npm worm that steals tokens',
                                'Rotate your npm, GitHub and cloud tokens, delete the package (and ~/.npm/_npx), and check GitHub for repos you did not make')
                yield from scan_text(body, f'{where} package {name} ({hook})')
    for f in files(*(f'{r}/lib/python3*/site-packages/*.pth' for r in PY_ENVS)):
        code = [l for l in text(f).splitlines() if l.startswith(('import ', 'import\t'))]
        if code:
            yield item(ver(f'Runs whenever this uvx/pipx tool starts: {tilde(f)}'))
            yield from scan_text('\n'.join(code), tilde(f))


@check('AI keys in plain text', FAM)
def keys():
    found = {}
    for f in files(*MCP_FILES, '~/.claude/settings.json', '~/.claude/settings.local.json', '~/.codex/config.toml', '~/.aider.conf.yml',
                   '~/.continue/config.yaml', '~/.config/litellm/*.yaml', '~/.config/fabric/.env', '~/.config/aichat/config.yaml',
                   '~/.config/io.datasette.llm/keys.json', '~/.claude/plugins/cache/*/*/*/.mcp.json', '~/.env'):
        if k := secret_kinds(text(f)): found[tilde(f)] = k
    for f, kinds in sorted(found.items()):
        yield warn(f'{f} holds {", ".join(kinds)} in plain text: any skill, plugin or npm install script can read it',
                   'Load keys from the environment or a keyring (secret-tool); at least chmod 600 the file')


@check('Local AI servers', FAM)
def local_servers():
    for l in sh('ss', '-tlnpH').splitlines():
        f = l.split()
        if len(f) < 4: continue
        addr, _, port = f[3].rpartition(':')
        if not port.isdigit() or int(port) not in AI_PORTS: continue
        proc = re.search(r'\(\("([^"]+)"', l)
        if proc and not AI_PROC.search(proc[1]): continue
        who = f'{AI_PORTS[int(port)]} ({proc[1] if proc else "port " + port})'
        if re.match(r'^(127\.|\[?::1\]?$)', addr) or addr.endswith('%lo'): yield item(f'{who} listens on this PC only')
        else: yield warn(f'{who} is reachable from your network on port {port} with no password',
                         'Bind it to 127.0.0.1 (Ollama: OLLAMA_HOST=127.0.0.1) or firewall the port')


@check('Editor extensions', FAM)
def extensions():
    for editor, root in EDITORS:
        meta = {e.get('identifier', {}).get('id', '').lower(): e.get('metadata', {}) for e in
                (jsonf(os.path.expanduser(f'{root}/extensions.json')) or []) if isinstance(e, dict)} if os.path.isdir(os.path.expanduser(root)) else {}
        for pj in files(f'{root}/*/package.json'):
            j = jsonf(pj)
            ext = f'{j.get("publisher", "?")}.{j.get("name", Path(pj).parent.name)}'
            side = ' (sideloaded from a .vsix)' if meta.get(ext.lower(), {}).get('source') == 'vsix' else ''
            yield item(f'{editor} extension: {ext}{side}')


# GlassWorm (2025) shipped VS Code / Open VSX extensions whose loader was a run of invisible variation selectors, decoded at run time.
INVISIBLE_CODE = re.compile(rb'(?:\xf3\xa0[\x84-\x87][\x80-\xbf]|\xef\xb8[\x80-\x8f]){8,}')
JS = ('.js', '.cjs', '.mjs', '.ts', '.jsx')


def invisible_code(root):
    """Script files under `root` (or inside it, for a Firefox .xpi) that carry a run of invisible variation selectors."""
    if root.endswith('.xpi'):
        try:
            with zipfile.ZipFile(root) as z: yield from (f'{root}!{n}' for n in z.namelist() if n.endswith(JS) and INVISIBLE_CODE.search(z.read(n)))
        except (OSError, zipfile.BadZipFile): pass
        return
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x != '.git']
        for f in fs:
            p = os.path.join(d, f)
            try:
                if f.endswith(JS) and os.path.getsize(p) < 32 << 20 and INVISIBLE_CODE.search(Path(p).read_bytes()): yield p
            except OSError: pass


@check('Extension code', FAM, slow=True)
def extension_code():
    from .persistence import CHROMIUM
    roots = [(e, f) for e, r in EDITORS for f in files(f'{r}/*')]
    roots += [(n, f) for n, sub, flat in CHROMIUM for f in files(f'~/.config/{sub}/*/Extensions/*', f'~/.var/app/{flat}/config/{sub}/*/Extensions/*')]
    roots += [('Firefox', f) for f in files('~/.mozilla/firefox/*/extensions/*.xpi', '~/.var/app/org.mozilla.firefox/.mozilla/firefox/*/extensions/*.xpi')]
    for app, ext in roots:
        if os.path.isdir(ext) or ext.endswith('.xpi'):
            for p in list(invisible_code(ext))[:1]:   # one row per extension
                yield alert(f'{app} extension {os.path.basename(ext)} hides code in invisible Unicode characters: {tilde(p)}',
                            'Remove the extension, then rotate GitHub, npm and Open VSX tokens and move any crypto wallet funds')


AI_CHAT = re.compile(r'chatgpt\.com|chat\.openai\.com|claude\.ai|gemini\.google\.com|bard\.google\.com|copilot\.microsoft\.com|'
                     r'perplexity\.ai|chat\.deepseek\.com|grok\.com|chat\.mistral\.ai|poe\.com|meta\.ai|chat\.qwen\.ai|aistudio\.google\.com')


@check('Extensions that read AI chats', FAM)
def chat_readers():
    # "Prompt poaching": AI sidebars and free VPNs that inject into the chat sites to copy every conversation.
    # ponytail: named chat sites only; an all-sites extension can read them too but is listed under Browser extensions.
    from .persistence import chromium_extensions, firefox_addons
    exts = [(b, t, eid, json.dumps([j.get('host_permissions'), j.get('permissions'), [c.get('matches') for c in j.get('content_scripts') or []
                                                                                     if isinstance(c, dict)]])) for b, t, eid, j in chromium_extensions()]
    exts += [('Firefox', (a.get('defaultLocale') or {}).get('name'), a.get('id'), json.dumps(a.get('userPermissions'))) for a in firefox_addons()]
    for browser, title, eid, perms in exts:
        if sites := sorted(set(AI_CHAT.findall(perms))):
            yield warn(f'{browser} extension {title} [{eid}] is built to read {", ".join(sites)}: it sees every prompt, reply and file you share there',
                       'Remove it unless you trust its maker with your AI conversations')


def repos():
    roots = {os.path.realpath(p) for p in jsonf(f'{HOME}/.claude.json').get('projects', {}) if os.path.isdir(p) and p != HOME}
    for d, dirs, _ in os.walk(HOME):
        if d.count('/') - HOME.count('/') >= 6: dirs[:] = []
        if '.git' in dirs: roots.add(d)
        dirs[:] = [x for x in dirs if x not in PRUNE and not (x.startswith('.') and d == HOME and x not in ('.config',))]
    return sorted(roots)


@check('Project agent configs', FAM)
def projects():
    for r in repos():
        rr = tilde(r)
        for path, name, s in servers(jsonf(f'{r}/.mcp.json') or {}): yield from judge_server(name, s, f'project {rr}')
        for f in files(f'{r}/.claude/settings.json', f'{r}/.claude/settings.local.json'):
            s = jsonf(f)
            yield from claude_settings(s, tilde(f))
            n = len(run_settings(s))
            for ev, groups in (s.get('hooks') or {}).items():
                for g in groups if isinstance(groups, list) else []:
                    for h in g.get('hooks', []) if isinstance(g, dict) else []:
                        n += 1
                        yield item(ver(f'Project hook {ev} ({rr}): {redact(h.get("command", ""))[:160]}'))
                        yield from scan_text(h.get('command', ''), f'Project hook {ev} ({rr})')
            if n and f.endswith('/settings.json'):   # settings.local.json is yours; settings.json is shared, so it comes with a clone
                yield warn(f'{tilde(f)} runs {n} command(s) whenever Claude Code works in {rr} (hooks, status line, helpers)',
                           "In a repo you cloned that is its authors' code: read it before trusting the folder")
        for t in (jsonc(f'{r}/.vscode/tasks.json').get('tasks') or []):
            if isinstance(t, dict) and (t.get('runOptions') or {}).get('runOn') == 'folderOpen':
                yield warn(f'{rr}/.vscode/tasks.json runs a command as soon as the folder is opened: {redact(t.get("command", ""))[:120]}',
                           'Remove "runOn": "folderOpen" unless you wrote it')
        for f in files(*(f'{r}/{x}' for x in INSTRUCTION_FILES), f'{r}/.cursor/rules/*', f'{r}/.claude/commands/*.md',
                       f'{r}/.claude/agents/*.md', f'{r}/.claude/skills/*/SKILL.md'):
            yield from scan_text(text(f), tilde(f))


SAFE_GLOBALS = re.compile(r'^(torch|collections|numpy|_codecs|copyreg|copy_reg|typing|pytorch_lightning|lightning|omegaconf|sklearn|'
                          r'transformers|tokenizers|safetensors|__builtin__\.(set|frozenset|slice|range|complex|bytearray|dict|list|tuple|int|float|str|bool|object)|'
                          r'builtins\.(set|frozenset|slice|range|complex|bytearray|dict|list|tuple|int|float|str|bool|object|bytes))(\.|$)')
BAD_GLOBALS = re.compile(r'^(os|posix|nt|subprocess|sys|socket|shutil|runpy|webbrowser|pty|commands|ctypes|importlib|pickle|_pickle|marshal|'
                         r'code|codeop|pdb|bdb|timeit|requests|urllib|http|httplib|aiohttp|asyncio|multiprocessing|signal|platform|'
                         r'(__builtin__|builtins)\.(eval|exec|execfile|compile|open|getattr|setattr|__import__|apply|breakpoint|input|globals|vars))(\.|$)')


def pickle_imports(f):
    """Every module.name a pickle stream imports (GLOBAL / STACK_GLOBAL), across the up-to-4 pickles a legacy torch file holds."""
    out, strs, memo = set(), [], {}
    for _ in range(4):
        try:
            for op, arg, _ in pickletools.genops(f):
                n = op.name
                if n in ('SHORT_BINUNICODE', 'BINUNICODE', 'UNICODE', 'BINUNICODE8', 'SHORT_BINSTRING', 'BINSTRING', 'STRING'): strs.append(str(arg))
                elif n in ('BINPUT', 'LONG_BINPUT', 'PUT') and strs: memo[arg] = strs[-1]
                elif n == 'MEMOIZE' and strs: memo[len(memo)] = strs[-1]
                elif n in ('BINGET', 'LONG_BINGET', 'GET') and arg in memo: strs.append(memo[arg])
                elif n in ('GLOBAL', 'INST'): out.add(str(arg).replace(' ', '.'))
                elif n == 'STACK_GLOBAL' and len(strs) >= 2: out.add(f'{strs[-2]}.{strs[-1]}')
        except Exception: break   # tensor bytes after the last pickle, or not a pickle at all
    return out


def model_imports(p):
    with open(p, 'rb') as f: head = f.read(4)
    if head == b'PK\x03\x04':
        with zipfile.ZipFile(p) as z:
            return set().union(*(pickle_imports(io.BytesIO(z.read(n))) for n in z.namelist() if n.endswith('.pkl')))
    if head[:1] == b'\x80' and 2 <= head[1] <= 5 or p.endswith(('.pkl', '.pickle')):
        with open(p, 'rb') as f: return pickle_imports(f)
    return set()


GGUF_SIZE = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}   # value type -> bytes; 8 string, 9 array
# Jinja server-side template injection: a chat template that walks into Python objects (CVE-2024-34359 and kin).
SSTI = re.compile(r'__(class|globals|subclasses|builtins|import|mro|bases?|init|getattribute|code|reduce)__|\bpopen\b|'
                  r'\bos\.system\b|\bsubprocess\b|\b(eval|exec|compile)\s*\(')


def gguf_templates(p):
    """The chat templates in a GGUF file's metadata: Jinja code llama.cpp, Ollama and LM Studio render."""
    import struct
    out = []
    with open(p, 'rb') as f:
        if f.read(4) != b'GGUF' or struct.unpack('<I', f.read(4))[0] < 2: return out   # v1 used 32-bit lengths
        u64 = lambda: struct.unpack('<Q', f.read(8))[0]
        def skip(t):
            if t == 8: f.seek(u64(), 1)
            elif t == 9:
                et, n = struct.unpack('<IQ', f.read(12))
                if et in GGUF_SIZE: f.seek(GGUF_SIZE[et] * n, 1)
                else:
                    for _ in range(n): skip(et)
            else: f.seek(GGUF_SIZE[t], 1)
        f.seek(8, 1)   # tensor count
        for _ in range(min(u64(), 10000)):
            k = f.read(u64()); t = struct.unpack('<I', f.read(4))[0]
            if t == 8 and k.startswith(b'tokenizer.chat_template'): out.append(f.read(u64()).decode('utf-8', 'replace'))
            else: skip(t)
    return out


def keras_lambda(p):
    """True when a Keras model has a Lambda layer: Python code that runs when the model is loaded."""
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z: cfg = z.read('config.json') if 'config.json' in z.namelist() else b''
    else:
        with open(p, 'rb') as f: cfg = f.read(8 << 20)   # .h5 keeps model_config as a JSON attribute near the start
    return bool(re.search(rb'"class_name":\s*"Lambda"', cfg))


def model_risks(p):
    """(severity, reason) for code hidden in a GGUF or Keras model file."""
    if p.endswith(('.keras', '.h5')):
        if keras_lambda(p): yield WARN, 'a Keras Lambda layer runs Python code when loaded'
        return
    for t in gguf_templates(p):
        m = SSTI.search(t)
        if m: yield ALERT, f'its chat template reaches into Python ({m[0]}): code runs when it is used for chat'
        for r in scan_text(t, p):
            if r[1] == ALERT: yield ALERT, f'its chat template: {r[0]}'


HF_HUB = os.path.join(os.environ.get('HF_HOME') or f'{HOME}/.cache/huggingface', 'hub')


@check('Hub model code', FAM)
def hub_code():
    # A Hugging Face model or dataset that ships .py files runs them when loaded with trust_remote_code=True (or as a datasets script).
    for repo in files(f'{HF_HUB}/models--*', f'{HF_HUB}/datasets--*'):
        kind, _, name = os.path.basename(repo).partition('--')
        name = name.replace('--', '/')
        pys = files(f'{repo}/snapshots/*/*.py', f'{repo}/snapshots/*/*/*.py')
        if pys: yield item(f'Hugging Face {kind[:-1]} {name} ships Python code that runs when it is loaded with trust_remote_code')
        for p in pys: yield from scan_text(text(p), f'Hugging Face {name} {os.path.basename(p)}')


@check('AI model files', FAM, slow=True)
def models():
    # Pickle-format models (.pt/.ckpt/.bin/.pkl) can run any code when loaded, Keras Lambda layers too, and a GGUF chat
    # template is Jinja code; safetensors are data only.
    n = 0
    for d, dirs, fs in os.walk(HOME):
        dirs[:] = [x for x in dirs if x not in PRUNE - {'.cache'} and not x.startswith(('.wine', 'compatdata'))]
        if d.count('/') - HOME.count('/') > 8: dirs[:] = []
        for f in fs:
            p = os.path.join(d, f)
            if f.endswith(('.gguf', '.keras', '.h5')) or f.startswith('sha256-') and '/.ollama/' in p:   # Ollama blobs are GGUF
                try: risks = list(model_risks(p))
                except (OSError, zipfile.BadZipFile, KeyError, struct_error, ValueError, MemoryError): continue
                for sev, why in dict.fromkeys(risks): yield (f'Model file {tilde(p)}: {why}', sev, f'Do not load it; quarantine {tilde(p)}')
                continue
            if not f.endswith(('.pt', '.pth', '.ckpt', '.bin', '.pkl', '.pickle', '.joblib')): continue
            try: imps = model_imports(p)
            except (OSError, zipfile.BadZipFile, ValueError): continue
            if imps: n += 1
            bad = sorted(i for i in imps if BAD_GLOBALS.match(i))
            odd = sorted(i for i in imps if not SAFE_GLOBALS.match(i) and not BAD_GLOBALS.match(i))
            if bad: yield alert(f'Model file runs code when loaded: {tilde(p)} imports {", ".join(bad)}', f'Do not load it; quarantine {tilde(p)}')
            elif odd: yield item(f'Model file imports unusual code: {tilde(p)}: {", ".join(odd[:5])}')
    if n: yield item('Pickle-format model files were checked for code that runs on load')
