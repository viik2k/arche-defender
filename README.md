# Arche Defender

An open-source security suite for Linux desktops in one window: malware and rootkit scans, a hardening audit,
persistence tripwires, threat intel, privacy and update checks, and a scanner for the AI agents, skills, plugins and
MCP servers you let act on your PC. It scores the machine, explains every finding with a fix, and remembers what was
there last time so only changes stand out.

Python 3 standard library only (plus tkinter for the window). No root needed, no telemetry. Scans are read-only:
the only things that change your system are actions you run yourself (quarantine, restore, the background monitor,
the threat-intel download).

Built on Nobara (Fedora, KDE Plasma) and written for any systemd desktop: package checks use `rpm` (Fedora, openSUSE),
`dpkg` (Debian, Ubuntu, Mint, Pop!_OS) or `pacman` (Arch, Manjaro, EndeavourOS), whichever owns the system; the rest is
plain Linux.

## Run

```sh
./arche-defender.py            # the window
./arche-defender.py --scan     # headless quick scan; exit 2 on alerts, 1 on warnings or new items, else 0
./arche-defender.py --scan --full --json > scan.json
./arche-defender.py --help     # every option and action
./arche-defender.py --version
```

Nothing to install: run it from the checkout. To get an `arche-defender` command instead, `pipx install .` from the
checkout (tkinter comes from your distro: `python3-tkinter` on Fedora, `python3-tk` on Debian/Ubuntu, `tk` on Arch).
Add it to the app menu, and **Scan with Arche Defender** and **Check AI skill or plugin before installing** entries to Dolphin's right-click menu, with `./arche-defender.py install-desktop`.

On the first run nothing is marked new because there is no baseline. Read through the findings, then click
**Accept as baseline** (or `--scan --accept`). Later scans mark anything that appeared since in amber.

**Quick scan** takes seconds and skips the slow checks. **Full scan** adds the deep malware scan, verification of
every packaged file, AI model files, browsing history against threat intel, Flatpak updates and ClamAV/YARA
when installed.

## What it checks

Every finding is an **alert** (red, -15 points), a **warning** (orange, -4) or an inventory item that is tracked
against the baseline (-1 when new). A check's warnings cost at most 8 and its new items at most 3, so one noisy area
cannot zero the score. Most come with a `fix:` line.
A finding you have judged harmless can be ignored (right-click it): that exact line stops counting, and nothing
else in the same check is hidden with it.
Every complete scan's score is kept, so the Overview shows whether the machine is getting safer (`history` prints it).

| Family | What it looks at |
|---|---|
| Threats | Heuristic and hash scan of the folders droppers use (Downloads, Desktop, /tmp, ~/.local/bin, app launchers), including inside zip archives (lures, password-protected zips holding programs), Linux programs packed with UPX or carrying miner-pool, reverse-shell or stealer strings, and documents that run code when opened (Office and LibreOffice macros, Excel 4.0 sheets, remote-template injection, DDE, RTF auto-update objects, PDF JavaScript and launch actions), a deeper scan of Documents, ~/.config, ~/.local/share and /opt, suspicious running processes, ClamAV/YARA, connections, DNS servers and hosts-file entries, browsing history, where downloaded files came from, and installed Chromium-family extensions matched against offline threat-intel feeds (over 8,000 extension IDs the Chrome Web Store pulled for malware); code in game mods (Steam Workshop items, BepInEx and MelonLoader plugins, r2modman and Gale profiles, Minecraft mod jars, Assetto Corsa apps, Lua mods in Proton games such as Balatro) checked for known malware, Discord-token and password stealing, chat-bot exfiltration and miners; traces of the Shai-Hulud npm worms (infected packages in node_modules, the SHA1HULUD GitHub runner backdoor in ~/.dev-env, worm workflows in your repositories) and any self-hosted GitHub runner on the PC; Windows programs in Wine, Proton, Bottles, Lutris and Heroic prefixes (hash-checked, plus their Run keys, Startup folders and Temp); ransom notes, and opt-in ransomware tripwire files that alarm when anything rewrites or renames them |
| AI agents | Claude Code, Codex, Gemini CLI, Cursor, VS Code, Windsurf, Cline, Continue, Zed, OpenClaw and friends: plugins, marketplaces, skills (ClawHub's included), hooks, MCP servers and Claude Desktop extensions (.mcpb), with each plugin and skill's code fingerprinted so an update that quietly changes what you approved shows up as new; skill, plugin and agent memory files (CLAUDE.md, OpenClaw workspace memory, saved memories) scanned for hidden Unicode instructions and invisible code, prompt injection, credential theft, malicious commands and the "prerequisite" lures that get you to run a stealer yourself (a password-protected archive to unpack and run, a downloaded program made executable, the macOS quarantine flag stripped); an OpenClaw gateway open to the LAN, open DMs or `dangerously*` switches on; agents allowed to run without asking (in settings, a shell alias that adds `--dangerously-skip-permissions` or `--yolo`, or a skill, command or agent whose `allowed-tools` pre-approves a whole shell), or running right now with approvals off; shell commands agents actually ran (Claude Code, Codex, Gemini CLI, OpenClaw transcripts) that sent an SSH key, cloud credentials, `.env` or the whole environment off the PC, or posted to a throwaway drop host, which is what a prompt-injected agent does; settings that route an agent's traffic through another host or proxy, or turn off TLS checks; unpinned `npx`/`uvx` MCP servers; the install scripts of npx/uvx-cached MCP servers and global AI CLIs, checked for what npm worms leave (Shai-Hulud, s1ngularity), and the npx and uvx MCP servers' own code checked for tool poisoning (hidden instructions in tool descriptions); plaintext API keys (the value is never shown); Ollama/LM Studio/ComfyUI open to the network; browser extensions built to read your ChatGPT, Claude or Gemini chats; repos' agent rules files (CLAUDE.md, AGENTS.md, `.cursor/rules`, Copilot instructions and prompts, Windsurf, Cline, Roo, Kiro, Amazon Q, Continue, Junie) scanned like skills for a "rules file backdoor"; repos that auto-run tasks or hooks, ship their own MCP servers (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, Gemini, Roo, Kiro, Amazon Q, opencode, Zed), or whose shared `.claude/settings.json` runs commands or asks to install plugins and marketplaces; settings that run commands (status line, key helpers) or load code through env vars (`NODE_OPTIONS`, `LD_PRELOAD`...); Hugging Face models and datasets that ship Python code (scanned like skills); every Ollama model, with its Modelfile system prompt, template and seeded messages scanned for injection; model files that run code when loaded (pickles, Keras Lambda layers, GGUF chat templates that break out of Jinja, Ollama blobs included); (full scan) editor and browser extension code hiding a GlassWorm-style invisible loader, and keys or tokens an agent read that are now stuck in its conversation history (Claude Code, Codex, Gemini CLI, opencode, Continue, Cursor, Windsurf, Copilot Chat; the kind and file are shown, never the value) |
| Protection | a firewall is on (firewalld, ufw or nftables), firewalld zones and open port ranges, update age, SELinux or AppArmor, Secure Boot, disk and swap encryption, kernel sysctls, autologin and screen lock, passwordless sudo, sshd config, permissions on SSH keys and token files (cloud and git logins, and AI sign-ins: Claude Code, Codex, Gemini, Copilot, mcp-remote OAuth, Hugging Face, Ollama), passphrase-less keys, setuid/setgid programs and file capabilities, Chromium/Electron apps running with their sandbox off; whether a backup exists (Pika, Deja Dup, Vorta, Kopia, Kup, btrbk, restic/borg timers or cron) and when it last ran, as opposed to same-disk snapshots only; LibreOffice macro security set to Low; Docker containers that can take over the PC (privileged, the Docker socket or `/` mounted, host PID, `SYS_ADMIN`, AppArmor/SELinux off), each container tracked so a new one shows up, and a daemon that takes commands over tcp without TLS or a socket every user can write |
| Integrity | the package manager's own checksums (`rpm -V`, `dpkg --verify`, `pacman -Qkk`) on the tools attackers swap (ls, ps, ss, sudo, sshd…), processes and kernel modules hidden from `/proc`, processes posing as kernel threads, code loaded from temp folders, LD_PRELOAD injection, promiscuous network cards, kernel taint |
| Persistence | XDG autostart, Plasma scripts, shell and X session rc files, systemd timers and services, cron, udev rules, ld.so.preload, PAM, shadowed sudo/ssh, browser extensions and native messaging hosts, out-of-tree kernel modules; command hooks people forget: D-Bus services that take over a system one, git config that runs commands (fsmonitor, sshCommand, `!` aliases and helpers), SSH ProxyCommand/LocalCommand, file-manager menus, Python `.pth` start-up code, app launchers that replace the system's own |
| Network | listening programs, hosts file, DNS, proxies, remote-desktop tools, SSH keys, shares, accounts; root certificates added to the system or to NSS/Firefox stores (a rogue one can read all HTTPS); saved open, WEP or WPA1 Wi-Fi that joins automatically; which listeners the firewall actually lets other machines reach (databases, RDP, VNC, Docker API flagged), container ports Docker publishes around firewalld, and (full scan) port forwards the router opened over UPnP; the router's hardware address and maker, and another device claiming it (ARP spoofing); tunnels that let the internet in past the router and firewall: Tailscale Funnel (a warning), Serve, SSH, subnet routes, exit nodes and Taildrive shares, and running ngrok, Cloudflare Tunnel, frp, playit.gg, chisel and similar, or ssh -R to serveo, localhost.run or pinggy (command lines, which often hold the tunnel token, are not shown) |
| Processes | programs running from temp or download folders, memfd, deleted binaries, executables no package owns |
| Activity | the last week of the journal: wrong-password bursts, SSH brute force and logins after it, new accounts, new admins, protections switched off through sudo or pkexec (SELinux permissive, firewall stopped or flushed, sudoers edited, kernel mitigations off, logs deleted); software installed or removed that week (dnf and Flatpak, routine upgrades left out) |
| Browsers | Safe Browsing switched off (Chromium family and Firefox), saved passwords, payment cards and sign-in cookies protected only by Chromium's built-in key (what infostealers replay to skip 2FA), Firefox saved passwords without a Primary Password, passwords Chrome's Password Checkup found in a breach or typed into a phishing site, Firefox proxies and security prefs turned down in about:config (unsigned extensions, old TLS, certificate pinning, mixed content, HSTS preload), managed browser policies that force extensions, proxies, search engines or certificates (how adware persists); browsers started (right now, by a launcher, or by a `*-flags.conf` file) with remote debugging on your real profile (how cookie stealers get past Chrome's app-bound encryption), `--load-extension`, `--ignore-certificate-errors` or a proxy; sites allowed to send notifications (the channel of fake virus-alert scams) or use the camera, microphone or location, with an alert for any on a threat list |
| Privacy | what is using the camera, microphone or screen right now; programs reading the keyboard or able to type as you through /dev/uinput (keyloggers), and membership of the input group; Flatpak apps allowed outside their sandbox; camera, location, screenshot and remote-control grants the desktop portals remember (remote control of mouse and keyboard without asking is a warning); passwords, tokens and keys left in shell and REPL history files (counted, never shown); copied passwords and keys that KDE or GNOME clipboard history saves to disk; secrets in the environment of crashed programs, which systemd-coredump logs to the journal (variable names only), and crash memory dumps of browsers, password managers and chat apps left readable on disk; Discord sign-in tokens any program can copy to log in as you past 2FA (Discord, Vesktop, Legcord); FileZilla server passwords saved without a master password and Remmina passwords kept outside the keyring; password-manager exports, private keys (OpenSSH keys with a passphrase told apart), tokens, card numbers and wallet recovery phrases saved as plain files in any of your folders, including copies of ~/.ssh and sign-in files left behind by a migration or backup (grouped per folder, only the kind is shown) |
| Devices | USB and Thunderbolt devices (a new "keyboard" can be a BadUSB), paired Bluetooth devices and KDE Connect phones |
| Updates | OS end of support, pending security updates, reboot needed, Flatpak and firmware updates, CPU vulnerability mitigations; every package source (dnf repos, apt sources, Flatpak remotes) and any that skip signature or TLS checks; where developer tools (pip, uv, npm, yarn, bun, cargo, go, git), and every cloned repo's own .npmrc, requirements.txt, pyproject.toml and .cargo/config, fetch code from: a second pip index (dependency confusion), TLS or Go checksum checks turned off, plain-HTTP sources, a Git password sent over HTTP, a token committed in a repo's config; apps that bundle their own Chromium (Electron: VS Code, Discord, Obsidian, AppImages and Flatpaks included) on an Electron version that no longer gets security fixes; known-vulnerable and malicious dependencies pinned in your code projects' lockfiles (npm, pnpm, Cargo, uv, requirements.txt) and in installed tools (MCP servers npx ran, global npm and pnpm packages, uv and pipx tools, pip --user packages, Claude Code), from the last `deps-update` |

Without root it cannot see other users' processes, `/root`, sudoers or the sshd config; those checks say so.

## Background monitor

```sh
./arche-defender.py install-monitor     # systemd user units: quick scan hourly, full scan weekly, plus a folder watch
./arche-defender.py monitor-status
./arche-defender.py uninstall-monitor
```

It runs at the lowest CPU and disk priority and sends a desktop notification only for findings it has not told you
about yet. Folder watches (systemd `.path` units) also re-run just the matching check within seconds of a change:
Downloads, Desktop and `~/.local/bin` (dropped files), autostart, user services, D-Bus services and launchers (persistence),
and Documents and Pictures (the ransomware tripwire, which runs at normal priority so a busy disk cannot delay it). No
daemon runs in between. The hourly pass also refreshes the threat-intel feeds once a day, the way antivirus updates its
definitions (offline, it keeps the last ones). Once you have run `deps-update` yourself, the weekly full pass repeats it.

## Actions

Also in the window's **Tools** menu.

| Action | Does |
|---|---|
| `intel-update` | downloads the threat-intel feeds; scans themselves never use the internet (the full-scan UPnP check only talks to your router) |
| `url-check URL` | checks a link before you open it, offline: threat-intel feeds plus phishing tricks (a familiar name used as a disguise, `user@` decoration, look-alike letters from other alphabets, `javascript:`/`data:` links, shorteners) |
| `deps-update` | checks the lockfiles of the code projects in your home folder, and installed developer and AI tools, against the OSV database (osv.dev: GitHub, PyPI, RustSec and OpenSSF malicious-package advisories); only packages from the public registries are sent, never private package names |
| `password-check` | tells you whether a password is in known data breaches (Have I Been Pwned range API: only the first 5 characters of its SHA-1 are sent) |
| `scan PATH` | scans a file or folder now, as closely as a download (threat-intel hashes, the built-in rules, archives and documents, ClamAV and YARA when installed) and prints what it found |
| `quarantine PATH` / `restore ID` / `quarantined` | moves a file into a locked folder and back |
| `canary-install` / `canary-remove` | puts a decoy PDF in Documents and Pictures; a scan (and the monitor) alarms if anything changes or renames it |
| `install-monitor` / `uninstall-monitor` / `monitor-status` | the background monitor |
| `vet PATH` | checks a skill, plugin, MCP server or extension before you install it (a folder, or a .zip, .skill, .mcpb, .vsix, .xpi or .crx): the AI and malware rules over every file, bundled dependencies included; the hooks, MCP servers and install scripts it would run on its own; wide `allowed-tools`; compiled programs it ships; password-protected archives refused. Prints a verdict and the code fingerprint the plugin will show once installed |
| `install-desktop` | adds it to the app menu, and **Scan with Arche Defender** and **Check AI skill or plugin before installing** to Dolphin's right-click menu (any action takes `--window` to show its result in a window) |
| `ignore "Check: text"` / `unignore "Check: text"` / `ignored` | hide one finding for good (in the window: right-click it), show it again, list them |
| `history` | the score of the last 20 complete scans |

### Threat-intel feeds

`intel-update` fetches keyless feeds: Feodo Tracker, SSLBL, Emerging Threats compromised IPs, Spamhaus DROP (v4 and v6),
signature-base C2 and hash IOCs, HaGeZi's threat-intel domains, OpenPhish's live phishing pages, and the Malicious Extension Sentry list of Chrome extension IDs removed for malware. Matching happens offline against connections, file
hashes and browsing history. It also fetches Electron's release list, to know which bundled browser engines are still patched. To also get **URLhaus** (malicious URLs, matched by exact URL), **MalwareBazaar** (sample
hashes from the last 48 hours) and **ThreatFox** (C2 IPs, domains, URLs and hashes), get a free Auth-Key at
<https://auth.abuse.ch/> and save it in `~/.config/arche-defender/abusech.key` (`chmod 600`) or `$ABUSECH_AUTH_KEY`.
Your own indicators (IPs, CIDRs, domains, hashes, one per line) go in `~/.config/arche-defender/iocs.txt`.

## Privacy of its own data

The baseline, quarantine, intel cache, score history and monitor state live in `~/.local/state/arche-defender/`, mode 700/600.
They describe your machine: do not publish them. Reports (**Save report**, HTML or JSON) contain the same and are
written mode 600. Secret files such as `~/.claude/.credentials.json` are only `stat`ed for their permissions, never read,
and detected API keys are reported by type and file, never by value.

## Development

```
arche-defender.py   launcher (same as python3 -m arche)
pyproject.toml      for pipx install; no dependencies
arche/core.py       check/action registry, baseline, scoring, helpers
arche/cli.py        arguments, headless scan, self-test
arche/gui.py        tkinter window (scans on worker threads)
arche/report.py     HTML/JSON reports
arche/<family>.py   the checks; every module in arche/ is loaded automatically
tests/test_*.py     run each with python3, or pytest from the repo root
```

A check is a generator registered with a decorator:

```python
from .core import check, alert, warn, item

@check('My check', 'Protection', slow=False)
def my_check():
    yield warn('Something is off', 'How to fix it')   # alert(), warn(), item()
```

`./arche-defender.py --selftest` runs every check, including the slow ones, and fails if any of them crashes.

It is a tripwire and an auditor, not a replacement for judgement: it shows what is there and what changed, and you
decide what it means.
