# AI agents: the newest way onto a PC is through the tools you let act for you. Inventories Claude Code, Codex, Gemini,
# Cursor, VS Code, Windsurf and friends (plugins, skills, hooks, MCP servers, editor extensions), scans their files for
# hidden instructions and malicious commands, flags settings that let an agent act without asking, finds plaintext API
# keys (never printing them), local model servers open to the network, and pickle model files that run code when loaded.
import hashlib, io, json, os, pickletools, re, zipfile
from struct import error as struct_error
from pathlib import Path
from .hardening import argv
from .core import HOME, ALERT, WARN, alert, warn, item, ver, sh, text, files, jsonf, check, action

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
    # ClawHavoc-style lures: a skill's "prerequisites" get the user to run the stealer themselves.
    ('tells you to unpack a password-protected archive (how ClawHub stealers got past scanners)', WARN,
     r'\b(extract|unzip|unpack|unrar|open)\b[^\n]{0,60}\b(with|using)\s+(the\s+)?password\b|\b(archive|zip|rar|7z)\s+password\s*[:=]',
     ('password',)),
    ('strips the macOS quarantine flag so Gatekeeper never checks the program', WARN, r'\bxattr\s+(-\w+\s+)*-[dc]\w*\s+(com\.apple\.quarantine)?', ('xattr',)),
    ('downloads a program, makes it executable and runs it', WARN,
     r'\b(curl|wget)\b[^\n]{0,200}?(-\w*[oO]\b|--output|>)\s*\S+[^\n]{0,120}\bchmod\s+(\+x|[0-7]*[157][0-7]{0,2})\b', ('chmod',)),
)]
SECRETS = (('Anthropic key', r'sk-ant-[\w-]{20,}'), ('OpenAI-style key', r'sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}'),
           ('GitHub token', r'gh[pousr]_[A-Za-z0-9]{30,}'), ('GitHub token', r'github_pat_\w{30,}'), ('Slack token', r'xox[abpr]-\d+-[\w-]{10,}'),
           ('Google key', r'AIza[\w-]{30,}'), ('Hugging Face token', r'hf_[A-Za-z0-9]{30,}'), ('GitLab token', r'glpat-[\w-]{20,}'),
           ('bearer token', r'Bearer (?=[\w.~+/=-]*\d)[\w.~+/=-]{16,}'), ('JWT', r'eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}'))
SECRET = re.compile('|'.join(p for _, p in SECRETS).replace('Bearer ', '(?<=Bearer )'))   # redact keeps the word "Bearer"
# ponytail: one literal-led pattern per kind, so re's fast prefix search runs: 6x quicker on GBs of transcripts than SECRET
SECRET_S = [(k, re.compile(p)) for k, p in SECRETS]
SECRET_B = [(k, re.compile(p.encode())) for k, p in SECRETS]
FAKE = r'(?i)x{5}|your|example|changeme|placeholder|redacted|dummy|abcdef|123456'   # docs, templates and test fixtures, not keys
FAKE_S, FAKE_B = re.compile(FAKE), re.compile(FAKE.encode())
SCAN_EXT = {'.md', '.sh', '.bash', '.py', '.js', '.mjs', '.cjs', '.ts', '.json', '.ps1', '.toml', '.yaml', '.yml', '.txt', ''}
PRUNE = {'node_modules', '.git', '.cache', '.local', '.var', '.steam', 'Steam', '.cargo', '.rustup', 'go', '.npm', '.nvm',
         'venv', '.venv', 'site-packages', 'target', 'dist', 'build', '.wine', 'Games', 'snap'}
AI_PORTS = {11434: 'Ollama', 1234: 'LM Studio', 8188: 'ComfyUI', 7860: 'Gradio / Stable Diffusion WebUI', 7861: 'Gradio',
            5001: 'KoboldCpp', 18789: 'OpenClaw gateway', 8080: 'llama.cpp / Open WebUI', 3000: 'Open WebUI', 9090: 'InvokeAI', 8000: 'vLLM'}
AI_PROC = re.compile(r'openclaw|ollama|llama|lms|lm-studio|comfy|python|koboldcpp|vllm|invokeai|open-webui|uvicorn|node', re.I)
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
             '~/.config/opencode/opencode.json', '~/.kiro/settings/mcp.json', '~/.aws/amazonq/mcp.json', '~/.lmstudio/mcp.json', '~/.copilot/mcp-config.json', '~/.qwen/settings.json',
             '~/.config/zed/settings.json')
PROJECT_MCP = ('.mcp.json', '.vscode/mcp.json', '.cursor/mcp.json', '.gemini/settings.json', '.roo/mcp.json', '.kiro/settings/mcp.json',
               '.amazonq/mcp.json', 'opencode.json', '.zed/settings.json')
MEMORY_FILES = ('~/.claude/CLAUDE.md', '~/.claude/memory/*.md', '~/.claude/projects/*/memory/*.md', '~/.codex/AGENTS.md', '~/.gemini/GEMINI.md',
                '~/.config/opencode/AGENTS.md', '~/.qwen/QWEN.md', '~/.windsurf/memories/*', '~/.codeium/windsurf/memories/*',
                '~/.openclaw/workspace/*.md', '~/.openclaw/workspace/memory/*.md')   # OpenClaw re-reads HEARTBEAT.md on a timer
CLAUDE_EXT = '~/.config/Claude/Claude Extensions'
SKILL_DIRS = ('~/.claude/skills', '~/.claude/commands', '~/.claude/agents', '~/.agents/skills', '~/.codex/skills', '~/.codex/prompts',
              '~/.gemini/extensions', '~/.gemini/commands', '~/.config/opencode/agent', '~/.config/opencode/command', '~/.cursor/rules',
              '~/.openclaw/skills', '~/.openclaw/workspace/skills',   # ClawHub skills: hundreds shipped stealers in 2026
              '~/.copilot/skills', '~/.copilot/agents', '~/.qwen/commands', '~/.qwen/agents')
COPILOT_PLUGINS = '~/.copilot/installed-plugins'   # GitHub Copilot CLI plugins: skills, agents, hooks and MCP servers, as Claude Code's
OPENCLAW = ('~/.openclaw/openclaw.json', '~/.clawdbot/clawdbot.json', '~/.moltbot/moltbot.json', '~/.openclaw/exec-approvals.json')
INSTRUCTION_FILES = ('CLAUDE.md', 'AGENTS.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.clinerules', '.clinerules/*', '.roorules',
                     '.rules', '.github/copilot-instructions.md', '.github/instructions/*', '.github/prompts/*', '.github/chatmodes/*',
                     '.windsurf/rules/*', '.roo/rules/*', '.roo/rules-*/*', '.kiro/steering/*', '.amazonq/rules/*', '.continue/rules/*',
                     '.junie/guidelines.md')   # the rules files a "rules file backdoor" hides instructions in


def tilde(p): return str(p).replace(HOME, '~', 1)
def redact(s): return re.sub(r'([?&][^=&\s]+=)[^&\s"]+', r'\1...', SECRET.sub('...', str(s)))


def jsonc(p):
    """JSON, tolerating the // comments and trailing commas VS Code and Zed allow."""
    t = text(p)
    try: return json.loads(t)
    except ValueError: pass
    t = re.sub(r'^\s*//[^\n]*$|/\*.*?\*/', '', t, flags=re.M | re.S)   # [^\n]: under re.S a .* comment ate the rest of the file
    try: return json.loads(re.sub(r',\s*([}\]])', r'\1', t))
    except ValueError: return {}


def scan_text(t, where):
    """Rule hits in one file or command: AI rules plus the malware rules when that module is present."""
    low, asc = t.lower(), t.isascii()   # the hint-less rules all hunt invisible Unicode: plain ASCII text cannot hold it
    hits = [(n, s, m.group(0)[:80]) for n, s, rx, h in AI_RULES if (not asc if h is None else any(x in low for x in h)) and (m := rx.search(t))]
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


def fingerprint(root, ext=None):
    """Short hash of every file under root (or of one file): it changes when a plugin or skill's code does,
    so an update that quietly swaps what you approved (a rug pull) shows up as new against the baseline."""
    h, paths = hashlib.sha256(), [root] if os.path.isfile(root) else sorted(
        os.path.join(d, f) for d, dirs, fs in os.walk(root) if not re.search(r'/(\.git|__pycache__)(/|$)', d) for f in fs
        if ext is None or os.path.splitext(f)[1].lower() in ext)   # ext: code only, for add-ons that ship gigabytes of weights
    # ponytail: __pycache__ is left out because running the plugin rewrites it; a planted .pyc is the scanners' job, not this one
    for p in paths:
        try:
            if os.path.islink(p): h.update(f'{os.path.relpath(p, root)}\0link\0{os.readlink(p)}\0'.encode()); continue
            h.update(f'{os.path.relpath(p, root)}\0{os.path.getsize(p)}\0'.encode())
            with open(p, 'rb') as fh:
                for b in iter(lambda: fh.read(1 << 20), b''): h.update(b)
        except OSError: pass
    return h.hexdigest()[:12]


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
    """Sorted kinds of key or token in t (str or bytes), never the values."""
    kinds = set()
    for k, p in SECRET_B if isinstance(t, bytes) else SECRET_S:
        for m in p.finditer(t):   # a key starts a word: not "task-...", not mid-base64 (a \b in the pattern would cost 15x)
            c, v = t[m.start() - 1:m.start()], m[0]
            if not (c.isalnum() or c in ('_', '-', '/', '+', b'_', b'-', b'/', b'+') or len(set(v)) < 12
                    or (FAKE_B if isinstance(t, bytes) else FAKE_S).search(v)): kinds.add(k); break
    return sorted(kinds)


def market_src(m):
    """Where a Claude Code plugin marketplace comes from: a GitHub repo, a git URL or a local path."""
    src = m.get('source') if isinstance(m, dict) and isinstance(m.get('source'), dict) else {}
    return str(src.get('repo') or src.get('url') or src.get('path') or '?')



def copilot_plugins():
    """Each installed Copilot CLI plugin: the folder holding plugin.json (at its root, or in .claude-plugin/ or .github/plugin/)."""
    pats = (f'{COPILOT_PLUGINS}/{d}{p}/plugin.json' for d in ('*', '*/*') for p in ('', '/.claude-plugin', '/.github/plugin'))
    return sorted({re.sub(r'/(\.claude-plugin|\.github/plugin)$', '', os.path.dirname(m)) for m in files(*pats)})

@check('AI plugins, skills and hooks', FAM)
def plugins():
    st = jsonf(f'{HOME}/.claude/settings.json')
    for k, on in (st.get('enabledPlugins') or {}).items():
        name, _, market = k.partition('@')
        d = max(files(f'~/.claude/plugins/cache/{market}/{name}/*'), key=os.path.getmtime, default=None)   # newest installed version
        yield item(f'Claude Code plugin {k} ({"enabled" if on else "disabled"})' + (f', code {fingerprint(d)}' if d else ''))
    for name, m in jsonf(f'{HOME}/.claude/plugins/known_marketplaces.json').items():
        yield item(f'Claude Code plugin marketplace {name}: {market_src(m)}')
    for root in SKILL_DIRS:
        for sk in files(f'{root}/*/SKILL.md', f'{root}/SKILL.md', f'{root}/*.md', f'{root}/*/gemini-extension.json'):
            nm = re.search(r'^name:\s*(.+)$', text(sk), re.M)
            whole = sk.endswith(('/SKILL.md', '/gemini-extension.json')) and os.path.dirname(sk) != os.path.expanduser(root)
            yield item(f'Skill/command {nm[1].strip() if nm else Path(sk).parent.name} ({tilde(sk)}), code {fingerprint(os.path.dirname(sk) if whole else sk)}')
    for f in files('~/.claude/settings.json', '~/.claude/settings.local.json', '/etc/claude-code/managed-settings.json',
                   '~/.claude/plugins/cache/*/*/*/hooks/hooks.json', '~/.claude/plugins/cache/*/*/*/hooks.json', *HOOK_FILES):
        where = re.sub(r'.*/plugins/cache/[^/]+/([^/]+)/.*', r'plugin \1', tilde(f))
        for ev, cmd in hook_cmds(jsonc(f)):
            yield item(ver(f'Hook {ev} ({where}): {redact(cmd)[:160]}'))
            yield from scan_text(cmd, f'Hook {ev} ({where})')
    for d in copilot_plugins(): yield item(f'Copilot CLI plugin {os.path.basename(d)} ({tilde(d)}), code {fingerprint(d)}')
    codex = text(f'{HOME}/.codex/config.toml')
    if m := re.search(r'^notify\s*=\s*(.+)$', codex, re.M): yield item(f'Codex notify hook: {redact(m[1])[:160]}')


@check('AI skill and plugin contents', FAM)
def contents():
    for d in files('~/.claude/plugins/cache/*/*/*'):
        if '/temp_git_' not in d: yield from scan_tree(d, 'plugin')
    for root in SKILL_DIRS:
        if os.path.isdir(os.path.expanduser(root)): yield from scan_tree(os.path.expanduser(root), 'skill')
    for d in files(f'{CLAUDE_EXT}/*'): yield from scan_tree(d, 'Claude Desktop extension')
    for d in copilot_plugins(): yield from scan_tree(d, 'Copilot CLI plugin')
    yield from preapproval_warns(files(*(f'{r}/{g}' for r in SKILL_DIRS for g in ('*/SKILL.md', 'SKILL.md', '*.md')),
                                       *(f'{r}/{g}' for r in ('~/.claude/plugins/cache/*/*/*', *copilot_plugins()) for g in ('skills/*/SKILL.md', 'commands/*.md', 'agents/*.md'))))
    # Agent memory and global instructions load into every session: an injection an agent was tricked into saving stays there.
    for f in files(*MEMORY_FILES): yield from scan_text(text(f), f'agent memory {tilde(f)}')


APPROVALS_OFF = re.compile(r'--dangerously-skip-permissions|--permission-mode[= ]+["\']?bypassPermissions|'
                          r'--dangerously-bypass-approvals-and-sandbox|--yolo\b|--allow-all(-tools)?\b|--trust-all-tools')   # --allow-all: Copilot CLI
# An API base URL in your shell start-up or session environment reroutes every agent and SDK that reads it (Claude Code, Codex,
# aider, the openai/anthropic libraries): that host gets each prompt, the files the agent reads, and the API key.
AI_BASE = re.compile(r'^\s*(?:export\s+|set\s+-\w*x\w*\s+)?((?:ANTHROPIC|OPENAI|GEMINI|GOOGLE_GEMINI|OPENROUTER|DEEPSEEK|MISTRAL|GROQ|XAI)_'
                     r'(?:API_)?BASE(?:_URL)?)\s*[=\s]\s*["\']?([^"\'\s]+)')
AI_HOSTS = re.compile(r'^https://([\w-]+\.)*(anthropic\.com|openai\.com|openai\.azure\.com|googleapis\.com|amazonaws\.com|openrouter\.ai|'
                      r'deepseek\.com|mistral\.ai|groq\.com|x\.ai)(:\d+)?(/|$)|^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/|$)')
CLOUD = re.compile(r'^https://([\w-]+\.)*(anthropic\.com|amazonaws\.com|googleapis\.com)(:\d+)?(/|$)')


@check('AI agent permissions', FAM)
def permissions():
    for f in files('~/.claude/settings.json', '~/.claude/settings.local.json', '/etc/claude-code/managed-settings.json'):
        yield from claude_settings(jsonf(f), tilde(f))
    codex = text(f'{HOME}/.codex/config.toml')
    if re.search(r'^\s*approval_policy\s*=\s*"never"', codex, re.M):
        yield warn('Codex runs commands without asking (approval_policy = "never")', 'Use "on-request" in ~/.codex/config.toml')
    if re.search(r'^\s*sandbox_mode\s*=\s*"danger-full-access"', codex, re.M):
        yield warn('Codex sandbox is off (sandbox_mode = "danger-full-access")', 'Use "workspace-write" in ~/.codex/config.toml')
    for u in re.findall(r'^\s*base_url\s*=\s*["\']([^"\']+)', codex, re.M):   # [model_providers.x]
        if not AI_HOSTS.match(u): yield warn(f'Codex sends its prompts, files and API key to {redact(u)[:80]} (base_url in ~/.codex/config.toml)',
                                             'Remove that model provider unless you run that server yourself')
    # ponytail: only an explicit GOOSE_MODE: an unset one is auto in recent Goose too, but varies by version
    if re.search(r'^GOOSE_MODE:\s*["\']?auto\b', text(f'{HOME}/.config/goose/config.yaml'), re.M):
        yield warn('Goose runs every tool without asking (GOOSE_MODE: auto)', 'Use smart_approve or approve: goose configure > Goose Settings > Mode')
    if re.search(r'"(yolo|autoAccept)"\s*:\s*true', text(f'{HOME}/.gemini/settings.json')):
        yield warn('Gemini CLI auto-accepts tool calls', 'Turn off autoAccept/yolo in ~/.gemini/settings.json')
    for f in files(*OPENCLAW):   # JSON5, so plain regexes rather than a parser
        t, where = text(f), tilde(f)
        for k in sorted(set(re.findall(r'["\']?(dangerously\w+|allowInsecureAuth)["\']?\s*:\s*true', t))):
            yield warn(f'OpenClaw has {k} switched on ({where})', f'Remove {k}: it turns off a protection of the gateway')
        if re.search(r'dmPolicy["\']?\s*:\s*["\']open', t):
            yield warn(f'OpenClaw takes orders from anyone who messages it (dmPolicy "open", {where}): a stranger can prompt-inject it',
                       'Use dmPolicy "pairing" or "allowlist"')
        if re.search(r'\bbind["\']?\s*:\s*["\'](lan|custom|0\.0\.0\.0)', t):
            yield warn(f'OpenClaw gateway is set to listen on your network ({where})', 'Use bind "loopback" (reach it remotely over Tailscale or SSH)')
        if re.search(r'\bsecurity["\']?\s*:\s*["\']full', t):
            yield warn(f'OpenClaw may run any shell command without asking (exec security "full", {where})', 'Use "allowlist"')
    from .persistence import RC_FILES
    for f in files(*RC_FILES, '~/.config/fish/functions/*.fish', '~/.bash_aliases', '~/.zsh_aliases', '~/.config/plasma-workspace/env/*.sh',
                   '~/.gemini/.env', '~/.env'):   # Gemini CLI loads both
        for l in text(f).splitlines():   # alias claude='claude --dangerously-skip-permissions': every session runs unguarded
            if APPROVALS_OFF.search(l) and not l.lstrip().startswith('#'):
                yield warn(f'{tilde(f)} starts an AI agent with approvals off: {redact(l.strip())[:120]}',
                           'Remove the flag; keep it for throwaway containers, where a bad command cannot reach your files')
            if (m := AI_BASE.match(l)) and not AI_HOSTS.match(m[2]):
                yield warn(f'{tilde(f)} sends AI agents\' traffic to {redact(m[2])[:80]} ({m[1]}): that server sees every prompt, '
                           'every file the agent reads, and your API key', f'Remove {m[1]} unless you run that server yourself')
    for f in files(*EDITOR_SETTINGS):
        s = jsonc(f)
        if s.get('chat.tools.autoApprove') is True or s.get('chat.tools.global.autoApprove') is True:
            yield warn(f'Editor chat agent runs tools without asking ({tilde(f)})', 'Set chat.tools.global.autoApprove to false')
        if s.get('security.workspace.trust.enabled') is False:
            yield warn(f'Workspace Trust is off ({tilde(f)}): opened folders can run tasks and extensions code', 'Set security.workspace.trust.enabled to true')
        if s.get('task.allowAutomaticTasks') == 'on':
            yield warn(f'Folders can start tasks automatically when opened ({tilde(f)})', 'Set task.allowAutomaticTasks to "off"')


HOOK_FILES = ('~/.gemini/settings.json', '~/.cursor/hooks.json', '~/.codeium/windsurf/hooks.json')
PROJECT_HOOKS = ('.gemini/settings.json', '.cursor/hooks.json', '.windsurf/hooks.json', '.github/hooks/*.json')   # last: Copilot


def hook_cmds(j):
    """(event, command) from a hooks block: Claude Code and Gemini CLI nest them in matcher groups, Cursor, Windsurf and Copilot list them."""
    hooks = j.get('hooks') if isinstance(j, dict) else None
    for ev, groups in (hooks if isinstance(hooks, dict) else {}).items():
        for g in groups if isinstance(groups, list) else []:
            for h in (g['hooks'] if isinstance(g.get('hooks'), list) else [g]) if isinstance(g, dict) else []:
                if isinstance(h, dict) and (cmd := h.get('command') or h.get('bash') or h.get('url') or h.get('prompt')): yield ev, str(cmd)


def run_settings(s):
    """(setting, command) for Claude Code settings that run a command, and env vars that make what it starts load code."""
    cmds = [(k, s[k]) for k in ('apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper') if isinstance(s.get(k), str)]
    if isinstance(s.get('statusLine'), dict) and s['statusLine'].get('type') == 'command': cmds.append(('statusLine', str(s['statusLine'].get('command', ''))))
    env = s.get('env') if isinstance(s.get('env'), dict) else {}
    return cmds + [(f'env {k}', str(v)) for k, v in env.items() if k in CODE_ENV]


# Allow rules that amount to "run anything": a whole shell, or an interpreter or downloader that can run any code.
WIDE_BASH = {'Bash', 'Bash(*)', 'Bash(*:*)', 'Bash(:*)', 'Bash(sudo:*)', 'Bash(curl:*)', 'Bash(wget:*)', 'Bash(sh:*)', 'Bash(bash:*)',
             'Bash(python:*)', 'Bash(python3:*)', 'Bash(node:*)', 'Bash(npx:*)', 'Bash(eval:*)'}


def preapproved(f):
    """Wide shell rules in a skill, command or agent's allowed-tools: while it is active the agent runs them without asking."""
    fm = re.match(r'---\r?\n(.*?)\n---', text(f), re.S)
    m = fm and re.search(r'^allowed-tools:(.*(?:\n[ \t]+-.*)*)', fm[1], re.M)
    return sorted({t.replace(' ', '') for t in re.findall(r'\bBash(?:\s*\([^)]*\))?', m[1])} & WIDE_BASH) if m else []


def preapproval_warns(fs):
    for f in fs:
        if w := preapproved(f):
            yield warn(f'{tilde(f)} pre-approves {", ".join(w)}: whatever it tells the agent to run happens without asking',
                       'Remove allowed-tools from it, or narrow it to the exact commands it needs')


def claude_settings(s, where):
    p = s.get('permissions') or {}
    if p.get('defaultMode') == 'bypassPermissions':
        yield warn(f'Claude Code skips all permission prompts by default ({where})', 'Remove "defaultMode": "bypassPermissions"')
    if s.get('skipDangerousModePermissionPrompt'): yield warn(f'Claude Code bypass-mode warning is turned off ({where})')
    wide = [a for a in p.get('allow', []) if a in WIDE_BASH]
    if wide: yield warn(f'Claude Code may run {", ".join(wide)} without asking ({where})', 'Allow specific commands instead of whole shells')
    if s.get('enableAllProjectMcpServers'):
        if where.endswith('settings.local.json') and '/.claude/' in where and not where.startswith('~/.claude/'):
            yield item(f'Claude Code auto-starts every MCP server in this project\'s .mcp.json ({where})')   # you approved it here
        else: yield warn(f'Claude Code auto-starts MCP servers from .mcp.json without asking ({where}): a cloned repo can run code',
                         'Remove "enableAllProjectMcpServers" and approve servers one by one')
    for k, c in run_settings(s):
        yield item(ver(f'Claude Code {k} ({where}) runs: {redact(c)[:160]}'))
        yield from scan_text(c, f'Claude Code {k} ({where})')
    env = s.get('env') if isinstance(s.get('env'), dict) else {}
    for k in ('ANTHROPIC_BASE_URL', 'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_VERTEX_BASE_URL', 'HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'):
        base = str(env.get(k) or '')   # a cloned repo's settings can send your key to its author before you trust it (CVE-2026-21852)
        if base and not (AI_HOSTS if k.endswith('BASE_URL') else CLOUD).match(base):   # a local router (LiteLLM) is fine, a local proxy is not
            yield warn(f'Claude Code traffic goes through {redact(base)} ({k}, {where}): that host sees every prompt and key',
                       f'Remove {k} unless you run that proxy yourself')
    if str(env.get('NODE_TLS_REJECT_UNAUTHORIZED', '')).strip() == '0':
        yield warn(f'Claude Code accepts any TLS certificate ({where}): anyone on your network can read and change its traffic',
                   'Remove NODE_TLS_REJECT_UNAUTHORIZED; for a company proxy use NODE_EXTRA_CA_CERTS instead')


CODE_ENV = {'NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'BASH_ENV', 'ENV', 'PYTHONSTARTUP', 'PYTHONPATH', 'PERL5OPT', 'RUBYOPT',
            'GIT_SSH_COMMAND', 'GIT_EXTERNAL_DIFF', 'GIT_ASKPASS', 'SSH_ASKPASS', 'PAGER', 'EDITOR', 'PROMPT_COMMAND', 'SHELL'}


AGENT_BYPASS = re.compile(r'^(--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo|--yes-always|'
                          r'--permission-mode=bypassPermissions|--approval-mode=yolo|--sandbox=danger-full-access)$')
AGENT_NAME = re.compile(r'openclaw|claude|codex|gemini|aider|opencode|goose|cursor-agent|qwen|amp|crush|cline', re.I)


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


GOOSE = '~/.config/goose/config.yaml'


def goose_extensions(t):
    """{name: server} from the extensions block of Goose's config.yaml, the plain YAML Goose writes itself (no YAML library here)."""
    out, cur, key = {}, None, None
    block = re.search(r'^extensions:[ \t]*\n((?:[ \t-].*\n?|\n)*)', t, re.M)
    for l in (block[1] if block else '').splitlines():
        if m := re.match(r'^  ([^\s:][^:]*):\s*$', l): cur, key = out.setdefault(m[1].strip('\'"'), {'args': [], 'env': {}}), None
        elif cur is None: continue
        elif m := re.match(r'^    (\w+):\s*(.*)$', l):
            key, v = m[1], m[2].strip().strip('\'"')
            if key in ('cmd', 'uri'): cur['command' if key == 'cmd' else 'url'] = v
            elif key == 'enabled' and v == 'false': cur['off'] = True
            elif key == 'args' and v.startswith('['): cur['args'] = [x.strip().strip('\'"') for x in v[1:-1].split(',') if x.strip()]
        elif key == 'args' and (m := re.match(r'^\s*- (.*)$', l)): cur['args'].append(m[1].strip().strip('\'"'))
        elif key == 'envs' and (m := re.match(r'^      (\w+):', l)): cur['env'][m[1]] = '...'   # names only: values are tokens
    return {n: s for n, s in out.items() if not s.pop('off', False) and ('command' in s or 'url' in s)}   # builtins have neither


def mcp_servers():
    """(where, name, server) for every MCP server configured in an agent, a plugin, a Desktop extension or Codex."""
    srcs = [(tilde(f), jsonc(f)) for f in files(*MCP_FILES)]
    srcs += [(re.sub(r'.*/plugins/cache/[^/]+/([^/]+)/.*', r'plugin \1', f), {'mcpServers': jsonf(f).get('mcpServers', jsonf(f))})
             for f in files('~/.claude/plugins/cache/*/*/*/.mcp.json')]
    srcs += [(f'Copilot CLI plugin {os.path.basename(d)}', jsonf(f'{d}/.mcp.json')) for d in copilot_plugins()]
    for where, conf in srcs:
        for path, name, s in servers(conf):
            yield tilde(where + (f' > {path[-1]}' if path and path[-1] not in ('mcp',) and where.endswith('.claude.json') else '')), name, s
    for mf in files(f'{CLAUDE_EXT}/*/manifest.json'):   # .mcpb/.dxt bundles: MCP servers that run unsandboxed
        j = jsonf(mf)
        yield 'Claude Desktop extension', j.get('display_name') or j.get('name') or Path(mf).parent.name, (j.get('server') or {}).get('mcp_config') or {}
    codex = text(f'{HOME}/.codex/config.toml')
    for name, body in re.findall(r'^\[mcp_servers\.([^\]]+)\]\n((?:[^\[].*\n?)*)', codex, re.M):
        cmd = re.search(r'^command\s*=\s*"([^"]*)"', body, re.M)
        args = re.findall(r'"([^"]*)"', (re.search(r'^args\s*=\s*\[(.*?)\]', body, re.M | re.S) or [''])[0] or '')
        url = re.search(r'^url\s*=\s*"([^"]*)"', body, re.M)
        yield '~/.codex/config.toml', name, {'command': cmd[1] if cmd else '', 'args': args, 'url': url[1] if url else ''}
    for name, s in goose_extensions(text(f'{HOME}/.config/goose/config.yaml')).items(): yield GOOSE, name, s


@check('MCP servers', FAM)
def mcp():
    loose = []
    for where, name, s in mcp_servers():
        yield from judge_server(name, s, where)
        if unpinned(s) and where != 'Claude Desktop extension': loose.append(name)
    if loose:
        yield warn(f'{len(loose)} MCP server(s) run whatever package version is newest (npx/uvx without a pinned version): '
                   f'{", ".join(sorted(set(loose)))}', 'Pin a version (pkg@1.2.3) so a hijacked release cannot run on your PC')


# Where npx/uvx keep the MCP servers they run, and where global AI CLIs (Claude Code, Codex, Gemini CLI) are installed.
NPM_ROOTS = ('~/.npm/_npx/*/node_modules', '~/.npm-global/lib/node_modules', '~/.nvm/versions/node/*/lib/node_modules',
             '~/.local/share/pnpm/global/*/node_modules', '~/.bun/install/global/node_modules', '/usr/lib/node_modules', '/usr/local/lib/node_modules')
PY_ENVS = ('~/.cache/uv/archive-v0/*', '~/.local/share/uv/tools/*', '~/.local/share/pipx/venvs/*')
# What npm worms left in install scripts: Shai-Hulud ran trufflehog for secrets, the Nx "s1ngularity" hack had AI CLIs hunt them.
WORM = re.compile(r'trufflehog|shai-?hulud|--dangerously-skip-permissions|--dangerously-bypass-approvals|--yolo\b|--trust-all-tools', re.I)


def uvx_package(s):
    """The package a uvx (or `uv tool run`) MCP server runs, without its version or extras."""
    c = [str(x) for x in [s.get('command', ''), *s.get('args', [])]]
    if not c: return None
    exe, rest = os.path.basename(c[0]), c[1:]
    if exe == 'uv' and rest[:2] == ['tool', 'run']: rest = rest[2:]
    elif exe != 'uvx': return None
    if '--from' in rest and rest.index('--from') + 1 < len(rest): return re.split(r'[\[=@<>~ ]', rest[rest.index('--from') + 1])[0]
    skip = False
    for a in rest:   # flags that take a value: uvx --python 3.12 --with x pkg
        if skip or a.startswith('-'): skip = a in ('--python', '-p', '--with', '-w', '--index', '--index-url', '--extra-index-url',
                                                   '--env-file', '--directory', '--with-requirements', '--constraint', '-c') and not skip; continue
        return re.split(r'[\[=@<>~ ]', a)[0]


def py_package_files(name):
    """A Python package's own .py files in the uvx/uv tool/pipx environments, from its RECORD (its dependencies are left out)."""
    norm = re.sub(r'[-_.]+', '_', name).lower()
    for rec in files(*(f'{r}/lib/python3*/site-packages/*.dist-info/RECORD' for r in PY_ENVS)):
        if re.sub(r'[-_.]+', '_', os.path.basename(os.path.dirname(rec)).split('-', 1)[0]).lower() == norm:
            sp = os.path.dirname(os.path.dirname(rec))
            yield from (os.path.normpath(os.path.join(sp, l.split(',')[0])) for l in text(rec).splitlines() if l.split(',')[0].endswith('.py'))


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
    for name in sorted({p for _, _, s in mcp_servers() if (p := uvx_package(s))}):   # uvx MCP servers: the same tool-poisoning scan as npx
        for f in dict.fromkeys(py_package_files(name)):
            if os.path.isfile(f) and os.path.getsize(f) < 8 << 20: yield from scan_text(text(f), f'MCP server package {name} {tilde(f)}')
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
                   '~/.config/io.datasette.llm/keys.json', '~/.claude/plugins/cache/*/*/*/.mcp.json', '~/.env', '~/.gemini/.env',
                   '~/.config/goose/config.yaml', '~/.config/goose/secrets.yaml',   # secrets.yaml: Goose's store when the keyring is off
                   *OPENCLAW, '~/.openclaw/.env', '~/.openclaw/agents/*/agent/auth-profiles.json'):
        if k := secret_kinds(text(f)): found[tilde(f)] = k
    for f, kinds in sorted(found.items()):
        yield warn(f'{f} holds {", ".join(kinds)} in plain text: any skill, plugin or npm install script can read it',
                   'Load keys from the environment or a keyring (secret-tool); at least chmod 600 the file')


JUPYTER = ('~/.jupyter/jupyter_server_config.py', '~/.jupyter/jupyter_notebook_config.py', '~/.jupyter/jupyter_lab_config.py',
           '~/.jupyter/jupyter_server_config.json', '~/.jupyter/jupyter_notebook_config.json')
J_APP = r'(?:ServerApp|NotebookApp|IdentityProvider)'
NO_TOKEN = re.compile(rf'''^\s*c\.{J_APP}\.token\s*=\s*u?(''|"")\s*(#.*)?$|"token"\s*:\s*""|--{J_APP}\.token=(''|""|(?=\s)|$)''', re.M)
J_PASSWORD = re.compile(r'''^\s*c\.\w+\.(hashed_)?password\s*=\s*u?['"][^'"]|"(hashed_)?password"\s*:\s*"[^"]|--\w+\.(hashed_)?password=\S''', re.M)
ANY_SITE = re.compile(r'''^\s*c\.\w+\.(allow_origin\s*=\s*['"]\*['"]|disable_check_xsrf\s*=\s*True)|"allow_origin"\s*:\s*"\*"|"disable_check_xsrf"\s*:\s*true|'''
                      r'''--\w+\.(allow_origin=['"]?\*|disable_check_xsrf=True)''', re.M)


def jupyter_rows(where, t):
    """Jupyter settings (a config file, or a running server's command line) that let others run code on this PC."""
    if NO_TOKEN.search(t) and not J_PASSWORD.search(t):
        yield warn(f'Jupyter runs code for anyone who reaches it: {where} turns its token off and sets no password',
                   'Remove the empty token (Jupyter then makes a new one at each start) or set a password: jupyter server password')
    if ANY_SITE.search(t):
        yield warn(f'Jupyter lets any website you open run code on this PC: {where} allows every origin or turns the XSRF check off',
                   'Remove allow_origin = "*" and disable_check_xsrf from it')


ANY_ORIGIN = re.compile(r'OLLAMA_ORIGINS=["\']?(?:[^"\'\s]*,)?(\*|https?://\*)(?=[,"\'\s]|$)')


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
    for f in files(*JUPYTER): yield from jupyter_rows(tilde(f), text(f))
    for cmd in sorted({l for l in sh('ps', '-eo', 'args', '--no-headers').splitlines() if 'jupyter' in l and '--' in l}):
        yield from jupyter_rows(f'the running server ({cmd[:100]})', cmd)
    # ponytail: the unit's Environment= and environment.d; an EnvironmentFile= or a shell export is not read
    env = ' '.join(sh('systemctl', *u, 'show', 'ollama', '-p', 'Environment', '--value') for u in ([], ['--user']))
    if ANY_ORIGIN.search(env + ' '.join(text(f) for f in files('~/.config/environment.d/*.conf', '/etc/environment'))):
        yield warn('Ollama answers any website (OLLAMA_ORIGINS=*): a page you open can run your models, pull new ones and delete them',
                   'Set OLLAMA_ORIGINS to only the apps that need it (such as chrome-extension://<id>), or remove it')


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
        for rel in PROJECT_MCP:   # a repo's own MCP config: Cursor once ran it on open (CurXecute, MCPoison)
            for path, name, s in servers(jsonc(f'{r}/{rel}') if os.path.isfile(f'{r}/{rel}') else {}):
                yield from judge_server(name, s, f'project {rr}' + (f', {rel}' if rel != '.mcp.json' else ''))
        for f in files(f'{r}/.claude/settings.json', f'{r}/.claude/settings.local.json'):
            s = jsonf(f)
            yield from claude_settings(s, tilde(f))
            n = len(run_settings(s))
            for ev, cmd in hook_cmds(s):
                n += 1
                yield item(ver(f'Project hook {ev} ({rr}): {redact(cmd)[:160]}'))
                yield from scan_text(cmd, f'Project hook {ev} ({rr})')
            if n and f.endswith('/settings.json'):   # settings.local.json is yours; settings.json is shared, so it comes with a clone
                yield warn(f'{tilde(f)} runs {n} command(s) whenever Claude Code works in {rr} (hooks, status line, helpers)',
                           "In a repo you cloned that is its authors' code: read it before trusting the folder")
            mk = s.get('extraKnownMarketplaces') if isinstance(s.get('extraKnownMarketplaces'), dict) else {}
            on = [k for k, v in s['enabledPlugins'].items() if v] if isinstance(s.get('enabledPlugins'), dict) else []
            if (mk or on) and f.endswith('/settings.json'):   # trusting the folder offers to install them; plugins bring hooks and MCP servers
                what = [f'marketplace {", ".join(f"{k} ({market_src(v)})" for k, v in mk.items())}' if mk else '',
                        f'plugins {", ".join(on)}' if on else '']
                yield warn(f'{tilde(f)} asks Claude Code to install {" and ".join(filter(None, what))} when you trust {rr}',
                           'In a repo you cloned, decline unless you know that marketplace; check a plugin first with: arche-defender vet FOLDER')
        for f in files(*(f'{r}/{g}' for g in PROJECT_HOOKS)):   # the same, for Gemini CLI, Cursor, Windsurf and Copilot
            hs = list(hook_cmds(jsonc(f)))
            for ev, cmd in hs:
                yield item(ver(f'Project hook {ev} ({rr}): {redact(cmd)[:160]}'))
                yield from scan_text(cmd, f'Project hook {ev} ({rr})')
            if hs: yield warn(f'{tilde(f)} runs {len(hs)} command(s) whenever an agent works in {rr} (hooks)',
                              "In a repo you cloned that is its authors' code: read it before trusting the folder")
        for t in (jsonc(f'{r}/.vscode/tasks.json').get('tasks') or []):
            if isinstance(t, dict) and (t.get('runOptions') or {}).get('runOn') == 'folderOpen':
                yield warn(f'{rr}/.vscode/tasks.json runs a command as soon as the folder is opened: {redact(t.get("command", ""))[:120]}',
                           'Remove "runOn": "folderOpen" unless you wrote it')
        for f in files(*(f'{r}/{x}' for x in INSTRUCTION_FILES), f'{r}/.cursor/rules/*', f'{r}/.claude/commands/*.md',
                       f'{r}/.claude/agents/*.md', f'{r}/.claude/skills/*/SKILL.md'):
            yield from scan_text(text(f), tilde(f))
        yield from preapproval_warns(files(f'{r}/.claude/commands/*.md', f'{r}/.claude/agents/*.md', f'{r}/.claude/skills/*/SKILL.md'))


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


CHATS = (('Claude Code', ('~/.claude/projects/*/*.jsonl', '~/.claude/projects/*/*/subagents/*.jsonl', '~/.claude/history.jsonl'),
          'Set "cleanupPeriodDays" in ~/.claude/settings.json to keep fewer days of history'),
         ('Codex', ('~/.codex/sessions/*/*/*/*.jsonl', '~/.codex/history.jsonl'), 'history.persistence = "none" in ~/.codex/config.toml stops the prompt log'),
         ('Gemini CLI', ('~/.gemini/tmp/*/chats/*.json', '~/.gemini/tmp/*/logs.json'), None),
         ('opencode', ('~/.local/share/opencode/storage/*/*/*.json', '~/.local/share/opencode/storage/*/*/*/*.json'), None),
         ('Continue', ('~/.continue/sessions/*.json',), None), ('OpenClaw', ('~/.openclaw/agents/*/sessions/*.jsonl',), None),
         ('Cursor', ('~/.config/Cursor/User/globalStorage/state.vscdb*', '~/.config/Cursor/User/workspaceStorage/*/state.vscdb*'), None),
         ('Windsurf', ('~/.config/Windsurf/User/globalStorage/state.vscdb*', '~/.config/Windsurf/User/workspaceStorage/*/state.vscdb*'), None),
         ('Copilot Chat', ('~/.config/Code/User/workspaceStorage/*/chatSessions/*.json',
                           '~/.config/Code/User/globalStorage/github.copilot-chat/session-store.db*'), None))


@check('Secrets in AI chat history', FAM, slow=True)
def chat_secrets():
    """Keys an agent read (a .env, a config, a pasted token) stay in its transcript, in plain text, for good."""
    for app, pats, tip in CHATS:
        fs = files(*pats)
        if not fs: continue
        yield item(f'{app} keeps your conversations in {tilde(os.path.commonpath(fs))}')
        hits = []
        for f in fs:
            try:
                with open(f, 'rb') as fh: b = fh.read(256 << 20)   # ponytail: first 256 MB of a transcript; stream it if they grow past that
            except OSError: continue
            if k := secret_kinds(b): hits.append((os.path.getmtime(f), f, k))
        for _, f, k in sorted(hits, reverse=True)[:10]:
            yield warn(f'{tilde(f)} ({app} conversation) holds {", ".join(k)} in plain text',
                       'Rotate the key: any skill, plugin or install script that reads your home folder gets it. '
                       f'Then delete the file{"; " + tip if tip else ""}')
        if len(hits) > 10: yield warn(f'{len(hits) - 10} more {app} conversations hold keys in plain text', tip)


# What a prompt-injected agent does with its shell: send a key file, the environment or saved logins off the PC.
SECRET_PATH = re.compile(r'\.ssh/id_[\w-]+\b(?!\.pub)|\.ssh/?(?=[\s"\']|$)|\.aws/credentials|\.netrc\b|\.git-credentials|'
                         r'\.claude/\.credentials\.json|\.codex/auth\.json|\.config/gh/hosts\.yml|\.kube/config|\.docker/config\.json|'
                         r'\.gnupg\b|\.password-store|(?<![\w.])\.env(?:\.(?!example|sample|template|dist)\w+)?(?![\w.])|wallet\.dat|Login Data|logins\.json|key4\.db|cookies\.sqlite')
SEND = re.compile(r'(@|<\s*|(?:-T|--upload-file|--post-file|--body-file)[=\s]+|\$\(\s*(?:cat|base64|head|tail|xxd)\s[^)]*?)["\']?\S*?'
                  r'(?P<p>' + SECRET_PATH.pattern + ')')
# ponytail: Discord webhooks and Telegram bots left out, homelab alerting posts to them too; known-bad hosts come from threat intel
DROP_HOST = re.compile(r'webhook\.site|requestbin|pipedream\.net|interact\.sh|\.oast\.\w+|burpcollaborator|ngrok(-free)?\.(io|app|dev)|'
                       r'transfer\.sh|0x0\.st|pastebin\.com|paste\.ee|hastebin')
NET = {'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'scp', 'rsync', 'sftp', 'ftp', 'xh', 'http', 'https', 'telnet'}
READERS = {'cat', 'base64', 'tar', 'gzip', 'zip', 'xz', 'zstd', 'xxd', 'od', 'gpg', 'openssl', 'head', 'tail', 'strings'}
HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n.*?\n\s*\1[ \t]*(?=\n|$)", re.S)
SHELL_TOOLS = {'Bash', 'shell', 'exec_command', 'run_shell_command', 'local_shell', 'exec', 'bash', 'execute_command', 'terminal'}
NET_HINT = re.compile(rb'\b(curl|wget|nc|ncat|netcat|socat|scp|rsync|sftp|ftp|xh|https?|telnet)\s')


def shell_commands(obj):
    """Commands an agent ran, from a transcript entry: Claude Code tool_use, Codex function_call, Gemini functionCall, OpenClaw exec."""
    if isinstance(obj, list):
        for x in obj: yield from shell_commands(x)
    if not isinstance(obj, dict): return
    if str(obj.get('name')) in SHELL_TOOLS or obj.get('type') == 'local_shell_call':
        p = obj.get('input') or obj.get('args') or obj.get('arguments') or obj.get('action') or {}
        if isinstance(p, str):
            try: p = json.loads(p)
            except ValueError: p = {'command': p}
        c = (p.get('command') or p.get('cmd') or '') if isinstance(p, dict) else ''
        if isinstance(c, list):   # Codex: ["bash", "-lc", "the command"]
            c = c[2] if len(c) > 2 and os.path.basename(str(c[0])) in ('bash', 'sh', 'zsh') else ' '.join(map(str, c))
        if c: yield str(c)
    for v in obj.values():
        if isinstance(v, (dict, list)): yield from shell_commands(v)


def tool(stage):
    """The program a pipeline stage runs, past sudo, nohup and VAR=value."""
    w = stage.split()
    while w and (w[0] in ('sudo', 'nohup', 'command', 'exec', 'time') or re.match(r'\w+=', w[0]) or w[0] == 'env' and len(w) > 1 and '=' in w[1]): w.pop(0)
    return os.path.basename(w[0].strip('(\'"')) if w else ''


def exfil(cmd):
    """(what, severity, the stage that sends it) for a shell command that sends a secret or data to a drop host, else None."""
    for line in re.split(r'\n|;|&&|\|\|', HEREDOC.sub('\n', cmd)):   # a heredoc's body is a script's text, not commands
        stages = [(tool(s), s) for s in line.split('|')]
        for i, (t, s) in enumerate(stages):
            if t not in NET: continue
            if m := SEND.search(s): return m['p'].strip('/'), ALERT, s
            args = s.split()[1:]
            if t in ('scp', 'rsync', 'sftp') and any(':' in a for a in args):
                if p := next((m[0] for a in args if ':' not in a and not a.startswith('-') and (m := SECRET_PATH.search(a))), None):
                    return p.strip('/'), ALERT, s
            for bt, bs in stages[:i]:
                if bt in ('env', 'printenv') and len(bs.split()) == 1: return 'all your environment variables (API keys included)', ALERT, line
                if bt in READERS and (m := SECRET_PATH.search(bs)): return m[0].strip('/'), ALERT, line
            if m := DROP_HOST.search(s): return f'data to {m[0]} (a throwaway drop host)', WARN, s
            for h in re.findall(r'https?://([\w.-]+)', s):
                if domain_hit and (hit := domain_hit(h)): return f'data to {h}, a known-bad host ({hit})', ALERT, s


@check('AI agent commands', FAM, slow=True)
def agent_commands():
    """Shell commands agents actually ran that send keys or the environment off the PC: what a prompt injection makes them do."""
    seen, hits = set(), []
    for app, pats, _ in CHATS:
        if app not in ('Claude Code', 'Codex', 'Gemini CLI', 'OpenClaw'): continue   # ponytail: the apps whose tool calls are plain JSON
        for f in files(*pats):
            try:
                with open(f, 'rb') as fh: rows = fh.read(256 << 20).splitlines() if f.endswith('.jsonl') else [fh.read(64 << 20)]
            except OSError: continue
            for row in rows:
                if not NET_HINT.search(row): continue
                try: entry = json.loads(row)
                except ValueError: continue
                for c in shell_commands(entry):
                    if c not in seen and (x := exfil(c)):
                        seen.add(c); hits.append((x[1], os.path.getmtime(f), app, f, *x))
    for sev, _, app, f, what, _, stage in sorted(hits, reverse=True)[:10]:
        yield (alert if sev == ALERT else warn)(
            f'{app} ran a command that sends {what} off this PC ({tilde(f)}): {redact(" ".join(stage.split()))[:140]}',
            'If you did not ask for it, the agent was likely prompt-injected: rotate that secret, and read what the session '
            'opened just before (a web page, an issue, a file) to find the injection')
    if len(hits) > 10: yield warn(f'{len(hits) - 10} more agent commands like these')


HF_HUB = os.path.join(os.environ.get('HF_HOME') or f'{HOME}/.cache/huggingface', 'hub')
OLLAMA = ('~/.ollama/models', '/usr/share/ollama/.ollama/models', '/var/lib/ollama/.ollama/models')   # user install, then the system service's


@check('Hub model code', FAM)
def hub_code():
    # A Hugging Face model or dataset that ships .py files runs them when loaded with trust_remote_code=True (or as a datasets script).
    for repo in files(f'{HF_HUB}/models--*', f'{HF_HUB}/datasets--*'):
        kind, _, name = os.path.basename(repo).partition('--')
        name = name.replace('--', '/')
        pys = files(f'{repo}/snapshots/*/*.py', f'{repo}/snapshots/*/*/*.py')
        if pys: yield item(f'Hugging Face {kind[:-1]} {name} ships Python code that runs when it is loaded with trust_remote_code')
        for p in pys: yield from scan_text(text(p), f'Hugging Face {name} {os.path.basename(p)}')
    # Ollama models: the inventory makes a newly pulled one stand out, and a Modelfile's system prompt, template or seeded
    # messages load into every chat with it, so they are scanned for injection like a skill.
    for root in OLLAMA:
        for mf in files(f'{root}/manifests/*/*/*/*'):
            host, ns, model, tag = mf.split('/')[-4:]
            name = f'{model}:{tag}' if (host, ns) == ('registry.ollama.ai', 'library') else f'{host}/{ns}/{model}:{tag}'
            yield item(f'Ollama model {name}')
            for layer in jsonf(mf).get('layers') or []:
                if str(layer.get('mediaType', '')).rsplit('.', 1)[-1] in ('system', 'template', 'messages', 'prompt'):
                    yield from scan_text(text(f'{root}/blobs/{str(layer.get("digest", "")).replace(":", "-")}'), f'Ollama model {name}')


ADDON_HOMES = ('~/ComfyUI', '~/Documents/ComfyUI', '~/.local/share/StabilityMatrix/Packages/*', '~/StabilityMatrix/Data/Packages/*',
               '~/pinokio/api/*/app')   # plus every git checkout repos() finds, and the ComfyUI desktop app's basePath
CODE_EXT = {'.py', '.js', '.mjs', '.cjs', '.ts', '.sh'}
DIRECT = re.compile(r'^\s*(?:([\w.-]+)\s*@\s*)?((?:git\+)?https?://[^\s;#]+)', re.M)


def addon_roots():
    """(kind, add-on folder, app folder) for each ComfyUI and Stable Diffusion WebUI (A1111, Forge) install."""
    base = jsonf(f'{HOME}/.config/ComfyUI/config.json')
    base = base.get('basePath') if isinstance(base, dict) else None
    for r in sorted({*repos(), *files(*ADDON_HOMES), *([base] if isinstance(base, str) else [])}):
        if os.path.isdir(f'{r}/custom_nodes') and (os.path.isdir(f'{r}/comfy') or os.path.isdir(f'{r}/models')):
            yield 'ComfyUI custom node', f'{r}/custom_nodes', r
        if os.path.isdir(f'{r}/extensions') and os.path.isfile(f'{r}/webui.py'): yield 'Stable Diffusion WebUI extension', f'{r}/extensions', r


def direct_reqs(t):
    """(package, host) for each requirements line that skips the package index: a wheel or repo fetched straight from a URL."""
    from urllib.parse import urlparse
    for name, url in DIRECT.findall(t):
        yield name or os.path.basename(url.split('#')[0]).split('-')[0].removesuffix('.git'), urlparse(url.removeprefix('git+')).hostname


def webui_args(t):
    """Launch flags set in a webui-user.sh (commented-out lines ignored)."""
    return ' '.join(re.findall(r'^\s*(?:export\s+)?COMMANDLINE_ARGS\s*=\s*["\']?([^"\'\n]*)', t, re.M)).split()


@check('ComfyUI and WebUI add-ons', FAM)
def addons():
    """ComfyUI custom nodes and Stable Diffusion WebUI extensions: other people's Python that runs unsandboxed as you every time the
    app starts (ComfyUI_LLMVISION stole browser passwords this way, through look-alike wheels in its requirements.txt)."""
    # ponytail: scans every text file of every add-on on each run; cache by fingerprint if a big install makes the quick scan slow
    for kind, d, app in addon_roots():
        for a in files(f'{d}/*'):
            n = os.path.basename(a)
            if n.startswith(('.', '__')) or not (os.path.isdir(a) or n.endswith('.py')): continue   # .disabled, __pycache__, README
            m = re.search(r'\[remote "origin"\][^\[]*?\burl\s*=\s*(\S+)', text(f'{a}/.git/config'))
            src = re.sub(r'//[^/@\s]+@', '//', m[1]) if m else 'no git remote'
            yield item(f'{kind} {n.removesuffix(".py")} ({tilde(a)}), from {src}, code {fingerprint(a, CODE_EXT)}')
            hits = scan_tree(a, kind) if os.path.isdir(a) else scan_text(text(a), f'{kind} {tilde(a)}')
            yield from ((t, sev, f'Remove {tilde(a)} unless you trust its author, then restart the app') for t, sev, _ in hits)
            for f in files(f'{a}/requirements*.txt'):
                for pkg, host in direct_reqs(text(f)): yield item(f'{kind} {n} installs {pkg} straight from {host}, not from PyPI ({tilde(f)})')
        for cfg in files(f'{app}/user/default/ComfyUI-Manager/config.ini', f'{app}/user/__manager/config.ini', f'{d}/ComfyUI-Manager/config.ini'):
            if re.search(r'^\s*security_level\s*=\s*weak\b', text(cfg), re.M | re.I):
                yield warn(f'ComfyUI-Manager in {tilde(app)} runs at security_level = weak: anyone who can open ComfyUI\'s page can install '
                           'custom nodes from any git URL and any pip package, which run as you', f'Set security_level = normal in {tilde(cfg)}')
        a = webui_args(text(f'{app}/webui-user.sh'))
        if '--enable-insecure-extension-access' in a and ({'--listen', '--share'} & set(a)):
            yield warn(f'Stable Diffusion WebUI in {tilde(app)} lets anyone who can reach it over the network install extensions, which run as you',
                       f'Remove --enable-insecure-extension-access from {tilde(app)}/webui-user.sh')
        if '--share' in a and not any(x.startswith('--gradio-auth') for x in a):
            yield warn(f'Stable Diffusion WebUI in {tilde(app)} is shared on a public gradio.live link with no password',
                       f'Add --gradio-auth user:password, or drop --share, in {tilde(app)}/webui-user.sh')


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


MAGIC = {b'\x7fELF': 'Linux program', b'MZ': 'Windows program', b'\xcf\xfa\xed\xfe': 'macOS program', b'\xca\xfe\xba\xbe': 'macOS program'}


def vet_rows(root):
    """Findings for an unpacked skill, plugin, MCP server or extension: rule hits in its text, the commands it runs on its own
    (hooks, MCP servers, install scripts), wide allowed-tools, and compiled programs nothing here can read."""
    from . import malware
    n, bins = 0, []
    for d, dirs, fs in os.walk(root) if os.path.isdir(root) else [(os.path.dirname(root), [], [os.path.basename(root)])]:
        dirs[:] = [x for x in dirs if x != '.git']   # node_modules stays: a bundled dependency is where a payload hides
        for f in fs:
            p, n = os.path.join(d, f), n + 1
            if n > 50000 or os.path.islink(p): continue
            try: st = os.lstat(p); head = open(p, 'rb').read(4)
            except OSError: continue
            if k := next((v for m, v in MAGIC.items() if head.startswith(m)), None): bins.append(p)
            if not k and os.path.splitext(f)[1].lower() in SCAN_EXT and st.st_size < 2 << 20: yield from scan_text(text(p), p)
            else: yield from malware.inspect(p, st, False, risky=True)   # hashes, lures, documents, nested zips
            if f == 'SKILL.md' or f.endswith('.md') and re.search(r'/(commands|agents)/', p): yield from preapproval_warns([p])
            if not f.endswith('.json'): continue
            j = jsonc(p)
            if not isinstance(j, dict): continue
            for ev, hs in (j.get('hooks') if isinstance(j.get('hooks'), dict) else {}).items():
                for c in re.findall(r'"command":\s*"((?:[^"\\]|\\.)*)"', json.dumps(hs)):
                    yield item(f'{p}: runs on every {ev}, without asking: {redact(json.loads(chr(34) + c + chr(34)))[:160]}')
            mcp = j.get('mcpServers') or ({'server': j['server']['mcp_config']} if isinstance(j.get('server'), dict) and j['server'].get('mcp_config') else {})
            for name, s in (mcp if isinstance(mcp, dict) else {}).items():
                if not isinstance(s, dict): continue
                yield item(f'{p}: starts MCP server {name}: {redact(" ".join(map(str, [s.get("command") or s.get("url") or s.get("httpUrl") or s.get("serverUrl", ""), *s.get("args", [])])))[:160]}')
                if unpinned(s): yield warn(f'{p}: MCP server {name} runs whatever version is newest at each start', 'Pin a version (pkg@1.2.3), or the author can change the code later')
            own = not re.search(r'/(node_modules|site-packages|\.?venv)/', p)   # a bundled dependency's install scripts already ran, on the author's PC
            scripts = j.get('scripts') if own and f == 'package.json' and isinstance(j.get('scripts'), dict) else {}
            for hook in ('preinstall', 'install', 'postinstall', 'prepare'):
                if cmd := scripts.get(hook):
                    yield (alert if WORM.search(str(cmd)) else warn)(f'{p}: runs on npm install ({hook}): {redact(cmd)[:160]}', 'Read what it runs before installing')
    if bins: yield warn(f'Ships {len(bins)} compiled program(s) this check cannot read: {", ".join(bins[:3])}' + (f' and {len(bins) - 3} more' if len(bins) > 3 else ''),
                        'Skills rarely need one. If a plugin does, get it from the project\'s own releases, or check it with ClamAV and VirusTotal')
    yield from malware.engine_hits([root], malware.clam([root]))


@action('vet', 'Check a skill, plugin, MCP server or extension before you install it: a folder, or a .zip, .skill, .mcpb, .vsix, .xpi or .crx',
        arg='path')
def vet(path):
    import shutil, tempfile
    src = os.path.abspath(os.path.expanduser(str(path).strip()))
    if not os.path.exists(src): return f'Not found: {src}'
    root, tmp = src, None
    if os.path.isfile(src) and zipfile.is_zipfile(src):   # a .crx's header in front of the zip is fine
        try:
            with zipfile.ZipFile(src) as z:
                infos = z.infolist()
                if any(i.flag_bits & 1 for i in infos):
                    return f'{src} is password-protected, so nothing can check what is inside. That is how ClawHub stealers got past scanners: do not install it.'
                if len(infos) > 50000 or sum(i.file_size for i in infos) > 1 << 30:
                    return f'{src} unpacks to over 1 GB or 50,000 files, which is not a skill or plugin (a zip bomb?). Not checked.'
                tmp = root = tempfile.mkdtemp(prefix='arche-vet-')
                z.extractall(tmp)   # zipfile drops absolute and ../ paths and writes links as plain files
            while len(ls := os.listdir(root)) == 1 and os.path.isdir(os.path.join(root, ls[0])): root = os.path.join(root, ls[0])   # skill-name/SKILL.md
        except (zipfile.BadZipFile, OSError, ValueError) as e:
            if tmp: shutil.rmtree(tmp, True)
            return f'Could not unpack {src}: {e}'
    try: rows, fp = list(vet_rows(root)), fingerprint(root)
    finally:
        if tmp: shutil.rmtree(tmp, True)
    name = (lambda s: s.replace(root + '/', '').replace(root, os.path.basename(src))) if tmp or os.path.isdir(src) else str
    rows = sorted({(name(t), s, f) for t, s, f in rows}, key=lambda r: (-r[1], r[0]))
    worst = max((s for _, s, _ in rows), default=0)
    tag = {ALERT: 'ALERT', WARN: 'WARN'}
    return '\n'.join([f'{src} (code {fp})', *(f'  [{tag.get(s, "info")}] {t}' + (f'\n      {f}' if f and s else '') for t, s, f in rows), '',
                      ('Verdict: do not install it.' if worst == ALERT else 'Verdict: read the warnings before you install it.' if worst == WARN else
                       'Verdict: nothing known-bad found. That is not proof it is safe: read its SKILL.md, hooks and scripts yourself.') +
                      f' Once installed, its fingerprint shows as "code {fp}" in AI plugins, skills and hooks if it is the same code.'])
