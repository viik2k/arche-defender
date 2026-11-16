# Background monitor: a systemd user timer runs a quick scan every hour (a full one once a week) and shows a desktop
# notification for alerts, warnings and new items it has not told you about yet. Folder watches (.path units) also
# re-run single checks within seconds of a change in Downloads, autostart, Documents... Nothing runs as root.
import json, os, re, sys, time
from pathlib import Path
from .core import STATE, ALERT, CHECKS, action, jsonf, write_private, sh, have, load_baseline, stamp, record

UNITS = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'systemd/user'
SEEN = STATE / 'notified.json'
LAUNCHER = Path(__file__).resolve().parent / '__main__.py'   # works from a git checkout and from a pipx install
WEEK = 7 * 86400
# Check -> folders whose change re-runs it within seconds (one .path unit each, not recursive): near-real-time
# download, persistence and ransomware detection with no daemon.
WATCH = {'Dropped files': ('%h/Downloads', '%h/Desktop', '%h/.local/bin'), 'Startup entries': ('%h/.config/autostart',),
         'Services': ('%h/.config/systemd/user',), 'Ransomware tripwire': ('%h/Documents', '%h/Pictures'),
         'Command hooks': ('%h/.local/share/dbus-1/services', '%h/.local/share/applications', '%h/.local/share/kio/servicemenus'),
         'Desktop add-ons': ('%h/.local/share/plasma/plasmoids', '%h/.local/share/kwin/scripts', '%h/.local/share/gnome-shell/extensions')}
ALSO = {'Ransomware tripwire': ('Encrypted files',)}   # same trigger: encryption that misses the decoys still alarms
URGENT = {'Ransomware tripwire'}   # runs at once and at normal priority: encryption saturates the disk, idle I/O would starve it


def fresh_findings(res, told):
    """{'check: text': sev} for every flagged row, and the ones not in `told` (what was already notified)."""
    flagged = {f'{n}: {r.text}': r.sev for n, rows in res.items() for r in rows if r.sev or r.new}
    return flagged, sorted((t for t in flagged if t not in told), key=lambda t: -flagged[t])


def run(only=None):
    """One pass: the hourly quick/full scan, or just the `only` checks (the folder watch)."""
    from .cli import pick, scan_all
    seen = jsonf(SEEN) or {}
    full = not only and time.time() - seen.get('full', 0) > WEEK
    if not only:   # fresh threat-intel feeds daily, the way an AV updates its definitions; offline keeps yesterday's
        from . import intel
        if (age := intel.feed_age_days()) is None or age >= 1:
            try: msg = intel.update()
            except Exception as e: msg = f'Failed: {type(e).__name__}'
            if 'Failed' in msg: print(f'threat intel update: {msg}', file=sys.stderr)
    if full:   # dependency advisories weekly, but only once you have run deps-update yourself: it sends package names to osv.dev
        from . import deps
        if deps.DB.exists():
            try: msg = deps.update()
            except Exception as e: msg = f'Could not update ({type(e).__name__})'
            if msg.startswith('Could not'): print(f'deps update: {msg}', file=sys.stderr)
    names = pick(full, only)
    res = scan_all(load_baseline(), names)
    told = set(seen.get('told', []))
    flagged, fresh = fresh_findings(res, told)
    if not only: record(res, 'full' if full else 'quick')
    if fresh and have('notify-send'):
        a = sum(flagged[t] == ALERT for t in fresh)
        title = f'Arche Defender: {len(fresh)} new finding{"s" * (len(fresh) > 1)}' + (f', {a} alert{"s" * (a > 1)}' if a else '')
        body = '\n'.join(t[:150] for t in fresh[:5]) + (f'\n…and {len(fresh) - 5} more' if len(fresh) > 5 else '') + '\nOpen Arche Defender to review.'
        sh('notify-send', '-a', 'Arche Defender', '-u', 'critical' if a else 'normal', '-i', 'security-low' if a else 'security-medium', title, body)
    # Only what is still flagged is remembered, so a problem that goes away and comes back is announced again.
    # ponytail: the timer and the folder watch can race on this file; the loser re-announces a finding once at worst.
    told = {t for t in told if not t.startswith(tuple(f'{n}: ' for n in names))} | set(flagged)
    write_private(SEEN, json.dumps({**seen, 'told': sorted(told)} if only else
                                   {'told': sorted(told), 'full': time.time() if full else seen.get('full', 0), 'last': stamp(),
                                    'last_kind': 'full' if full else 'quick', 'fresh': len(fresh)}, indent=1))
    print(f'{len(flagged)} flagged, {len(fresh)} new' + (' (full scan)' if full else ''))
    return 0


def drop_watches():
    """Stop and delete every folder-watch unit (also ones from older versions or checks that no longer exist)."""
    old = sorted(p.name for p in UNITS.glob('arche-defender-watch*'))
    if old: sh('systemctl', '--user', 'disable', '--now', *old)
    for u in old: (UNITS / u).unlink(missing_ok=True)


@action('install-monitor', 'scan in the background every hour (full scan weekly) and notify about new findings')
def install():
    UNITS.mkdir(parents=True, exist_ok=True)
    (UNITS / 'arche-defender.service').write_text(f'''[Unit]
Description=Arche Defender background scan

[Service]
Type=oneshot
ExecStart="{sys.executable}" "{LAUNCHER}" --monitor
Nice=19
IOSchedulingClass=idle
''')
    (UNITS / 'arche-defender.timer').write_text('''[Unit]
Description=Arche Defender hourly scan

[Timer]
OnCalendar=hourly
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
''')
    drop_watches()
    watches = []
    for check, dirs in WATCH.items():
        if check not in CHECKS: continue
        u = 'arche-defender-watch-' + re.sub(r'\W+', '-', check.lower()).strip('-')
        (UNITS / f'{u}.service').write_text(f'''[Unit]
Description=Arche Defender: {check} after a change

[Service]
Type=oneshot
''' + ('' if check in URGENT else 'ExecStartPre=/bin/sleep 3\n') + f'''ExecStart="{sys.executable}" "{LAUNCHER}" --monitor --only "{check}"''' + ''.join(f' --only "{x}"' for x in ALSO.get(check, ()) if x in CHECKS) + '''
''' + ('' if check in URGENT else 'Nice=19\nIOSchedulingClass=idle\n'))
        (UNITS / f'{u}.path').write_text('[Unit]\nDescription=Arche Defender: watch for ' + check + '\n\n[Path]\n' +
                                         ''.join(f'PathChanged={d}\n' for d in dirs) + '\n[Install]\nWantedBy=default.target\n')
        watches.append(f'{u}.path')
    sh('systemctl', '--user', 'daemon-reload')
    out = sh('systemctl', '--user', 'enable', '--now', 'arche-defender.timer', *watches, err=True).strip()
    on = sh('systemctl', '--user', 'is-active', 'arche-defender.timer').strip() == 'active'
    return (f'Background monitor on: an hourly scan, and {len(watches)} folder watches (Downloads, autostart, Documents...). '
            f'Turn off with: arche-defender uninstall-monitor' if on else f'Could not start the timer: {out or "is systemd --user running?"}')


@action('install-desktop', 'add Arche Defender to the app menu')
def desktop():
    p = Path(os.environ.get('XDG_DATA_HOME') or Path.home() / '.local/share') / 'applications/arche-defender.desktop'
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f'''[Desktop Entry]
Type=Application
Name=Arche Defender
Comment=Security scan for this PC
Exec="{sys.executable}" "{LAUNCHER}"
Icon=security-high
Categories=System;Security;
StartupWMClass=Arche-defender
''')
    # Dolphin's right-click menu; KF6 ignores a service menu that is not executable.
    # ponytail: KDE only; a Nautilus script or Nemo action is the same few lines when someone on GNOME/Cinnamon wants it
    m = p.parent.parent / 'kio/servicemenus/arche-defender-scan.desktop'
    m.parent.mkdir(parents=True, exist_ok=True)
    m.write_text(f'''[Desktop Entry]
Type=Service
MimeType=all/allfiles;inode/directory;
Actions=scan;vet
X-KDE-Priority=TopLevel

[Desktop Action scan]
Name=Scan with Arche Defender
Icon=security-high
Exec="{sys.executable}" "{LAUNCHER}" --window scan %f

[Desktop Action vet]
Name=Check AI skill or plugin before installing
Icon=security-medium
Exec="{sys.executable}" "{LAUNCHER}" --window vet %f
''')
    m.chmod(0o755)
    return f'Added to the app menu ({p}) and to the file manager\'s right-click menu ({m}); delete those files to remove them'


@action('uninstall-monitor', 'stop the background monitor')
def uninstall():
    drop_watches()
    sh('systemctl', '--user', 'disable', '--now', 'arche-defender.timer')
    for u in ('arche-defender.timer', 'arche-defender.service'): (UNITS / u).unlink(missing_ok=True)
    sh('systemctl', '--user', 'daemon-reload')
    return 'Background monitor removed.'


@action('monitor-status', 'when the background monitor last ran and what it found')
def status():
    s, on = jsonf(SEEN) or {}, sh('systemctl', '--user', 'is-active', 'arche-defender.timer').strip() == 'active'
    nxt = sh('systemctl', '--user', 'show', 'arche-defender.timer', '-p', 'NextElapseUSecRealtime', '--value').strip()
    return (f'Monitor {"on" if on else "off"}' + (f', next run {nxt}' if on and nxt else '') +
            (f'. Last {s.get("last_kind", "")} scan {s["last"]}: {len(s.get("told", []))} flagged, {s.get("fresh", 0)} new.' if s.get('last') else '. Never ran.'))
