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
Add it to the app menu with `./arche-defender.py install-desktop`.

On the first run nothing is marked new because there is no baseline. Read through the findings, then click
**Accept as baseline** (or `--scan --accept`). Later scans mark anything that appeared since in amber.

**Quick scan** takes seconds and skips the slow checks. **Full scan** adds the deep malware scan, verification of
every packaged file, AI model files, browsing history against threat intel, Flatpak updates and ClamAV/YARA
when installed.

## What it checks

Every finding is an **alert** (red, -15 points), a **warning** (orange, -4) or an inventory item that is tracked
against the baseline (-1 when new). Most come with a `fix:` line.
A finding you have judged harmless can be ignored (right-click it): that exact line stops counting, and nothing
else in the same check is hidden with it.
Every complete scan's score is kept, so the Overview shows whether the machine is getting safer (`history` prints it).

| Family | What it looks at |
|---|---|
| Threats | Heuristic and hash scan of the folders droppers use (Downloads, Desktop, /tmp, ~/.local/bin, app launchers), including inside zip archives (lures, password-protected zips holding programs) and documents that run code when opened (Office and LibreOffice macros, Excel 4.0 sheets, remote-template injection, DDE, RTF auto-update objects, PDF JavaScript and launch actions), a deeper scan of Documents, ~/.config, ~/.local/share and /opt, suspicious running processes, ClamAV/YARA, connections and browsing history matched against offline threat-intel feeds; Windows programs in Wine, Proton, Bottles, Lutris and Heroic prefixes (hash-checked, plus their Run keys, Startup folders and Temp); ransom notes, and opt-in ransomware tripwire files that alarm when anything rewrites or renames them |
| AI agents | Claude Code, Codex, Gemini CLI, Cursor, VS Code, Windsurf, Cline, Continue, Zed and friends: plugins, marketplaces, skills, hooks, MCP servers and Claude Desktop extensions (.mcpb); skill, plugin and agent memory files (CLAUDE.md, saved memories) scanned for hidden Unicode instructions and invisible code, prompt injection, credential theft and malicious commands; agents allowed to run without asking, or running right now with approvals off; unpinned `npx`/`uvx` MCP servers; the install scripts of npx/uvx-cached MCP servers and global AI CLIs, checked for what npm worms leave (Shai-Hulud, s1ngularity); plaintext API keys (the value is never shown); Ollama/LM Studio/ComfyUI open to the network; browser extensions built to read your ChatGPT, Claude or Gemini chats; repos that auto-run tasks or hooks, or whose shared `.claude/settings.json` runs commands; settings that run commands (status line, key helpers) or load code through env vars (`NODE_OPTIONS`, `LD_PRELOAD`...); Hugging Face models and datasets that ship Python code (scanned like skills); model files that run code when loaded (pickles, Keras Lambda layers, GGUF chat templates that break out of Jinja, Ollama blobs included); (full scan) editor and browser extension code hiding a GlassWorm-style invisible loader |
| Protection | a firewall is on (firewalld, ufw or nftables), firewalld zones and open port ranges, update age, SELinux or AppArmor, Secure Boot, disk encryption, kernel sysctls, autologin and screen lock, passwordless sudo, sshd config, permissions on SSH keys and token files, passphrase-less keys, setuid/setgid programs and file capabilities, Chromium/Electron apps running with their sandbox off; whether a backup exists (Pika, Deja Dup, Vorta, Kopia, Kup, btrbk, restic/borg timers or cron) and when it last ran, as opposed to same-disk snapshots only; LibreOffice macro security set to Low |
| Integrity | the package manager's own checksums (`rpm -V`, `dpkg --verify`, `pacman -Qkk`) on the tools attackers swap (ls, ps, ss, sudo, sshd…), processes and kernel modules hidden from `/proc`, processes posing as kernel threads, code loaded from temp folders, LD_PRELOAD injection, promiscuous network cards, kernel taint |
| Persistence | XDG autostart, Plasma scripts, shell and X session rc files, systemd timers and services, cron, udev rules, ld.so.preload, PAM, shadowed sudo/ssh, browser extensions and native messaging hosts, out-of-tree kernel modules; command hooks people forget: D-Bus services that take over a system one, git config that runs commands (fsmonitor, sshCommand, `!` aliases and helpers), SSH ProxyCommand/LocalCommand, file-manager menus, Python `.pth` start-up code, app launchers that replace the system's own |
| Network | listening programs, hosts file, DNS, proxies, remote-desktop tools, SSH keys, shares, accounts; root certificates added to the system or to NSS/Firefox stores (a rogue one can read all HTTPS); saved open, WEP or WPA1 Wi-Fi that joins automatically; which listeners the firewall actually lets other machines reach (databases, RDP, VNC, Docker API flagged), container ports Docker publishes around firewalld, and (full scan) port forwards the router opened over UPnP; the router's hardware address and maker, and another device claiming it (ARP spoofing) |
| Processes | programs running from temp or download folders, memfd, deleted binaries, executables no package owns |
| Activity | the last week of the journal: wrong-password bursts, SSH brute force and logins after it, new accounts, new admins; software installed or removed that week (dnf and Flatpak, routine upgrades left out) |
| Browsers | Safe Browsing switched off (Chromium family and Firefox), saved passwords protected only by Chromium's built-in key, Firefox proxies, managed browser policies that force extensions, proxies, search engines or certificates (how adware persists) |
| Privacy | what is using the camera, microphone or screen right now; Flatpak apps allowed outside their sandbox; passwords, tokens and keys left in shell and REPL history files (counted, never shown) |
| Devices | USB and Thunderbolt devices (a new "keyboard" can be a BadUSB), paired Bluetooth devices and KDE Connect phones |
| Updates | OS end of support, pending security updates, reboot needed, Flatpak and firmware updates, CPU vulnerability mitigations; every package source (dnf repos, apt sources, Flatpak remotes) and any that skip signature or TLS checks |

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
daemon runs in between.

## Actions

Also in the window's **Tools** menu.

| Action | Does |
|---|---|
| `intel-update` | downloads the threat-intel feeds; scans themselves never use the internet (the full-scan UPnP check only talks to your router) |
| `password-check` | tells you whether a password is in known data breaches (Have I Been Pwned range API: only the first 5 characters of its SHA-1 are sent) |
| `quarantine PATH` / `restore ID` / `quarantined` | moves a file into a locked folder and back |
| `canary-install` / `canary-remove` | puts a decoy PDF in Documents and Pictures; a scan (and the monitor) alarms if anything changes or renames it |
| `install-monitor` / `uninstall-monitor` / `monitor-status` | the background monitor |
| `install-desktop` | adds it to the app menu |
| `ignore "Check: text"` / `unignore "Check: text"` / `ignored` | hide one finding for good (in the window: right-click it), show it again, list them |
| `history` | the score of the last 20 complete scans |

### Threat-intel feeds

`intel-update` fetches keyless feeds: Feodo Tracker, SSLBL, Emerging Threats compromised IPs, Spamhaus DROP (v4 and v6),
signature-base C2 and hash IOCs, and HaGeZi's threat-intel domains. Matching happens offline against connections, file
hashes and browsing history. To also get **URLhaus** (malicious URLs, matched by exact URL), **MalwareBazaar** (sample
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
