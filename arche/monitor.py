# Background monitor: a systemd user timer runs a quick scan every hour (a full one once a week) and shows a desktop
# notification for alerts, warnings and new items it has not told you about yet. A .path unit also re-runs the few
# checks for Downloads and autostart within seconds of something landing there. Nothing runs as root.
import json, os, sys, time
from pathlib import Path
from .core import STATE, ALERT, action, jsonf, write_private, sh, have, load_baseline, stamp, record

UNITS = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'systemd/user'
SEEN = STATE / 'notified.json'
LAUNCHER = Path(__file__).resolve().parent.parent / 'arche-defender.py'
WEEK = 7 * 86400
# Folders watched for changes, and the checks a change re-runs: near-real-time download and persistence scanning, no daemon.
WATCH = {'%h/Downloads': 'Dropped files', '%h/Desktop': 'Dropped files', '%h/.local/bin': 'Dropped files',
         '%h/.config/autostart': 'Startup entries', '%h/.config/systemd/user': 'Services'}


def fresh_findings(res, told):
    """{'check: text': sev} for every flagged row, and the ones not in `told` (what was already notified)."""
    flagged = {f'{n}: {r.text}': r.sev for n, rows in res.items() for r in rows if r.sev or r.new}
    return flagged, sorted((t for t in flagged if t not in told), key=lambda t: -flagged[t])


def run(only=None):
    """One pass: the hourly quick/full scan, or just the `only` checks (the folder watch)."""
    from .cli import pick, scan_all
    seen = jsonf(SEEN) or {}
    full = not only and time.time() - seen.get('full', 0) > WEEK
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
    only = ' '.join(f'--only "{c}"' for c in dict.fromkeys(WATCH.values()))
    (UNITS / 'arche-defender-watch.service').write_text(f'''[Unit]
Description=Arche Defender scan of a watched folder

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 5
ExecStart="{sys.executable}" "{LAUNCHER}" --monitor {only}
Nice=19
IOSchedulingClass=idle
''')
    (UNITS / 'arche-defender-watch.path').write_text('''[Unit]
Description=Arche Defender: scan new downloads and autostart entries

[Path]
''' + ''.join(f'PathChanged={d}\n' for d in WATCH) + '''Unit=arche-defender-watch.service

[Install]
WantedBy=default.target
''')
    sh('systemctl', '--user', 'daemon-reload')
    out = sh('systemctl', '--user', 'enable', '--now', 'arche-defender.timer', 'arche-defender-watch.path', err=True).strip()
    on = sh('systemctl', '--user', 'is-active', 'arche-defender.timer').strip() == 'active'
    return (f'Background monitor on: an hourly scan, and Downloads, Desktop, ~/.local/bin and autostart are watched. '
            f'Turn off with: arche-defender uninstall-monitor' if on else f'Could not start the timer: {out or "is systemd --user running?"}')


@action('uninstall-monitor', 'stop the background monitor')
def uninstall():
    units = ('arche-defender.timer', 'arche-defender.service', 'arche-defender-watch.path', 'arche-defender-watch.service')
    sh('systemctl', '--user', 'disable', '--now', *units)
    for u in units: (UNITS / u).unlink(missing_ok=True)
    sh('systemctl', '--user', 'daemon-reload')
    return 'Background monitor removed.'


@action('monitor-status', 'when the background monitor last ran and what it found')
def status():
    s, on = jsonf(SEEN) or {}, sh('systemctl', '--user', 'is-active', 'arche-defender.timer').strip() == 'active'
    nxt = sh('systemctl', '--user', 'show', 'arche-defender.timer', '-p', 'NextElapseUSecRealtime', '--value').strip()
    return (f'Monitor {"on" if on else "off"}' + (f', next run {nxt}' if on and nxt else '') +
            (f'. Last {s.get("last_kind", "")} scan {s["last"]}: {len(s.get("told", []))} flagged, {s.get("fresh", 0)} new.' if s.get('last') else '. Never ran.'))
