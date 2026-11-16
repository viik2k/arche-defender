# Protection status: is the machine's own armour on (firewall, SELinux, Secure Boot, updates)?
import os, time
from .core import alert, warn, item, sh, files, check


@check('Security posture', 'Protection')
def security():
    fw = sh('systemctl', 'is-active', 'firewalld').strip()
    if fw != 'active': yield alert(f'Firewall (firewalld) is {fw or "missing"}')
    for db in files('/usr/lib/sysimage/rpm/rpmdb.sqlite', '/var/lib/rpm/rpmdb.sqlite')[:1]:
        age = int((time.time() - os.path.getmtime(db)) / 86400)
        if age > 14: yield alert(f'No package updates in {age} days')
    yield item('SELinux: ' + (sh('getenforce').strip() or 'not installed'))
    sb = sh('mokutil', '--sb-state').strip()
    if sb: yield item(sb)
