# Background monitor: a systemd user timer runs a quick scan every hour (a full one once a week) and shows a desktop
# notification for alerts, warnings and new items it has not told you about yet. Nothing runs as root.
import json, os, sys, time
from pathlib import Path
from .core import STATE, ALERT, action, jsonf, write_private, sh, have, load_baseline, stamp

UNITS = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'systemd/user'
SEEN = STATE / 'notified.json'
LAUNCHER = Path(__file__).resolve().parent.parent / 'arche-defender.py'
WEEK = 7 * 86400


def fresh_findings(res, told):
    """{'check: text': sev} for every flagged row, and the ones not in `told` (what was already notified)."""
    flagged = {f'{n}: {r.text}': r.sev for n, rows in res.items() for r in rows if r.sev or r.new}
    return flagged, sorted((t for t in flagged if t not in told), key=lambda t: -flagged[t])


def run():
    from .cli import pick, scan_all
    seen = jsonf(SEEN) or {}
    full = time.time() - seen.get('full', 0) > WEEK
    res = scan_all(load_baseline(), pick(full))
    flagged, fresh = fresh_findings(res, set(seen.get('told', [])))
    if fresh and have('notify-send'):
        a = sum(flagged[t] == ALERT for t in fresh)
        title = f'Arche Defender: {len(fresh)} new finding{"s" * (len(fresh) > 1)}' + (f', {a} alert{"s" * (a > 1)}' if a else '')
        body = '\n'.join(t[:150] for t in fresh[:5]) + (f'\n…and {len(fresh) - 5} more' if len(fresh) > 5 else '') + '\nOpen Arche Defender to review.'
        sh('notify-send', '-a', 'Arche Defender', '-u', 'critical' if a else 'normal', '-i', 'security-low' if a else 'security-medium', title, body)
    # Only what is still flagged is remembered, so a problem that goes away and comes back is announced again.
    write_private(SEEN, json.dumps({'told': sorted(flagged), 'full': time.time() if full else seen.get('full', 0), 'last': stamp(),
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
    sh('systemctl', '--user', 'daemon-reload')
    out = sh('systemctl', '--user', 'enable', '--now', 'arche-defender.timer', err=True).strip()
    on = sh('systemctl', '--user', 'is-active', 'arche-defender.timer').strip() == 'active'
    return (f'Background monitor on: {UNITS}/arche-defender.timer runs hourly. Turn off with: arche-defender uninstall-monitor'
            if on else f'Could not start the timer: {out or "is systemd --user running?"}')


@action('uninstall-monitor', 'stop the background monitor')
def uninstall():
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
