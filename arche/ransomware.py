# Ransomware tripwire: decoy files the user opts into (canary-install), checked on every scan and by the background
# monitor. Ransomware encrypts or renames everything it reaches, so a changed or renamed decoy is an early alarm.
# Ransom notes are spotted by malware.py's file sweep.
import hashlib, json, os
from pathlib import Path
from .core import check, action, alert, warn, item, jsonf, write_private, STATE, HOME

DB = STATE / 'canaries.json'
NAME = 'Tax return 2025 (Arche Defender tripwire - do not open or delete).pdf'
WHERE = ('Documents', 'Pictures')


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


@action('canary-install', 'Put ransomware tripwire files in Documents and Pictures (a scan alarms if anything changes them)')
def install():
    db = jsonf(DB)
    for d in WHERE:
        if not os.path.isdir(f'{HOME}/{d}'): continue
        p = f'{HOME}/{d}/{NAME}'
        if not os.path.exists(p):
            Path(p).write_bytes(b'%PDF-1.4\n%' + os.urandom(4096).hex().encode() + b'\n%%EOF\n')
        db[p] = sha(p)
    write_private(DB, json.dumps(db, indent=1))
    return 'Tripwires set: ' + ', '.join(db) if db else 'No Documents or Pictures folder to put a tripwire in.'


@action('canary-remove', 'Delete the ransomware tripwire files')
def remove():
    db = jsonf(DB)
    for p, h in db.items():
        try:
            if sha(p) == h: os.remove(p)   # ponytail: a changed one is left for the user to look at
        except OSError: pass
    try: DB.unlink()
    except OSError: pass
    return f'Removed {len(db)} tripwires.'


@check('Ransomware tripwire', 'Threats')
def tripwire():
    """Each decoy must still exist, unchanged, under its own name; a copy with an extra extension is how most ransomware renames."""
    db = jsonf(DB)
    if not db:
        yield item('Ransomware tripwire is off', fix='Run: arche-defender canary-install (puts one decoy PDF in Documents and Pictures).')
        return
    for p, h in db.items():
        renamed = [f for f in (os.listdir(os.path.dirname(p)) if os.path.isdir(os.path.dirname(p)) else [])
                   if f.startswith(os.path.basename(p)) and f != os.path.basename(p)]
        try: changed = sha(p) != h
        except OSError: changed = None
        if renamed or changed:
            yield alert(f'Ransomware tripwire {"renamed to " + renamed[0] if renamed else "changed"}: {p}',
                        fix='Something rewrote a file nobody should touch. Disconnect from the network, shut down, and restore from an offline backup; do not pay.')
        elif changed is None:
            yield warn(f'Ransomware tripwire is missing: {p}', fix='If you deleted it, run canary-install again; if not, check other files in that folder.')
