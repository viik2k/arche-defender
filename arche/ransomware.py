# Ransomware tripwire: decoy files the user opts into (canary-install), checked on every scan and by the background
# monitor. Ransomware encrypts or renames everything it reaches, so a changed or renamed decoy is an early alarm.
# Ransom notes are spotted by malware.py's file sweep. 'Backups' checks there is a copy to restore from.
import hashlib, json, math, os, re, time
from collections import Counter
from datetime import datetime
from pathlib import Path
from .core import check, action, alert, warn, item, sh, have, text, files, jsonf, write_private, STATE, HOME
from .malware import walk

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


# Encrypted files: ransomware that misses the decoys still leaves files whose name promises a format their bytes no longer have.
DATA_EXT = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf', 'epub', 'zip', '7z', 'rar', 'gz', 'jpg', 'jpeg',
            'png', 'gif', 'webp', 'tif', 'tiff', 'heic', 'mp3', 'm4a', 'flac', 'ogg', 'wav', 'mp4', 'mov', 'mkv', 'webm', 'avi'}
MAGIC = (b'PK\x03\x04', b'PK\x05\x06', b'\xd0\xcf\x11\xe0', b'\xff\xd8\xff', b'\x89PNG', b'GIF8', b'RIFF', b'\x1aE\xdf\xa3', b'fLaC',
         b'OggS', b'7z\xbc\xaf', b'\x1f\x8b', b'Rar!', b'ID3', b'{\\rtf', b'II*\0', b'MM\0*')
USER_DIRS = ('Documents', 'Pictures', 'Desktop', 'Music', 'Videos', 'Downloads')


def ciphertext(h):
    """No known file signature, and bytes as even as random data (compressed formats all start with a signature)."""
    if h.startswith(MAGIC) or h[4:8] == b'ftyp' or b'%PDF' in h[:1024] or (h[:1] == b'\xff' and h[1] & 0xe0 == 0xe0): return False
    return -sum(c / len(h) * math.log2(c / len(h)) for c in Counter(h).values()) > 7.6


def encrypted(roots, since):
    """(path, extension added by a rename or '') for files changed since `since` that look encrypted."""
    for p, st in walk(roots, 6):
        parts = os.path.basename(p).lower().split('.')
        ext, added = (parts[-1], '') if parts[-1] in DATA_EXT else (parts[-2], parts[-1]) if len(parts) > 2 and parts[-2] in DATA_EXT else ('', '')
        if not ext or st.st_mtime < since or st.st_size < 1024: continue
        try:
            with open(p, 'rb') as f: h = f.read(4096)
        except OSError: continue
        if ciphertext(h): yield p, added


@check('Encrypted files', 'Threats')
def encrypted_files():
    """Documents, photos and media changed in the last week that no longer look like what their names say."""
    found = list(encrypted([f'{HOME}/{d}' for d in USER_DIRS], time.time() - 7 * 86400))
    if not found: return
    added = Counter(a for _, a in found if a).most_common(1)
    yield (alert if len(found) >= 3 else warn)(
        (f'{len(found)} files changed this week no longer look like what their names say' if len(found) > 1 else
         '1 file changed this week no longer looks like what its name says') + ', as if encrypted'
        + (f' (renamed to *.{added[0][0]})' if added else '') + ': ' + ', '.join(p.replace(HOME, '~') for p, _ in found[:3]),
        fix='If they no longer open: disconnect from the network, shut down, and restore from an offline backup. Do not pay; '
            'look for a free decryptor at nomoreransom.org first. A single damaged download can also look like this.')


STALE = 14   # days
BACKUP_RE = re.compile(r'backup|restic|borg|kopia|btrbk|rsnapshot|duplicity|duplicati|rclone|syncoid|zrepl', re.I)
APPS = {'Pika Backup': ('~/.config/pika-backup/config.json', '~/.var/app/org.gnome.World.PikaBackup/config/pika-backup/config.json'),
        'Vorta (borg)': ('~/.local/share/Vorta/settings.db', '~/.var/app/com.borgbase.Vorta/data/Vorta/settings.db'),
        'Kopia': ('~/.config/kopia/repository.config',), 'Kup': ('~/.config/kuprc',), 'btrbk': ('/etc/btrbk/btrbk.conf',)}


def epoch(iso):
    try: return datetime.fromisoformat(iso).timestamp()
    except ValueError: return None


def find_backups():
    """(kind, description, last run epoch or None); kind 'backup' is a copy elsewhere, 'snapshot' stays on the same disk."""
    for name, paths in APPS.items():
        if files(*paths): yield 'backup', name, None
    dd = re.search(r"last-backup='([^']+)'", text(f'{HOME}/.var/app/org.gnome.DejaDup/config/glib-2.0/settings/keyfile')) or \
         (re.search(r"'([^']+)'", sh('gsettings', 'get', 'org.gnome.DejaDup', 'last-backup')) if have('deja-dup') else None)
    if dd: yield 'backup', 'Deja Dup', epoch(dd[1])
    for user in ((), ('--user',)):
        try: timers = json.loads(sh('systemctl', *user, 'list-timers', '--all', '-o', 'json', timeout=10) or '[]')
        except ValueError: timers = []
        for t in timers:
            name = f"{t.get('unit')} ({t.get('activates')})"
            if 'snapper' in name: continue   # snapper configs are listed below
            if BACKUP_RE.search(name): yield 'backup', f'timer {t.get("unit")}', (t.get('last') or 0) / 1e6 or None
    cron = text('/etc/crontab').splitlines() + [l for f in files('/etc/cron.d/*') for l in text(f).splitlines()] + \
           sh('crontab', '-l').splitlines() + [os.path.basename(f) for f in files('/etc/cron.daily/*', '/etc/cron.weekly/*')]
    for l in cron:
        if BACKUP_RE.search(l) and not l.lstrip().startswith('#'): yield 'backup', f'cron job {l.strip()[:80]}', None
    ts = jsonf('/etc/timeshift/timeshift.json')
    if ts and ts.get('do_first_run') != 'true' and any(ts.get(f'schedule_{p}') == 'true' for p in ('monthly', 'weekly', 'daily', 'hourly', 'boot')):
        yield 'snapshot', 'Timeshift (system files; the home folder is excluded unless you added it)', None
    for f in files('/etc/snapper/configs/*'):
        if m := re.search(r'^SUBVOLUME="([^"]+)"', text(f), re.M): yield 'snapshot', f'snapper {os.path.basename(f)} ({m[1]})', None


def backup_rows(found, now=None):
    now, found = now or time.time(), list(found)
    for kind, desc, last in found:
        age = int((now - last) / 86400) if last else None
        if kind == 'backup' and age is not None and age > STALE:
            yield warn(f'Backup {desc} last ran {age} days ago', fix='Check it still works (drive plugged in, repository reachable) and run it now.')
        else: yield item(f'{"Backup" if kind == "backup" else "Snapshots"}: {desc}')   # ponytail: no date in item text, or every scan is "new"
    if not any(k == 'backup' for k, _, _ in found):
        snaps = [d.split(' (')[0] for k, d, _ in found if k == 'snapshot']
        yield warn('No backup of your files found' + (f' (only same-disk snapshots: {", ".join(snaps)})' if snaps else ''),
                   fix='Back up to an external drive or another machine: Pika Backup or Deja Dup (Flathub), or restic/borg on a timer. '
                       'Keep one copy unplugged: ransomware encrypts every drive it can reach.')


@check('Backups', 'Protection')
def backups():
    """Is there a copy of your files to restore from? Backup apps, backup timers and cron jobs, and same-disk snapshots."""
    yield from backup_rows(find_backups())
