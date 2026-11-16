# Run: python3 tests/test_integrity.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.integrity import rpm_verify


def test_rpm_verify():
    out = '''..?......    /usr/bin/sudo
S.5....T.    /usr/bin/ls
S.5....T.  c /etc/sudoers
missing     /usr/sbin/sshd
missing     /var/db/sudo/lectured (Permission denied)
.......T.  d /usr/share/doc/x
..5......    /usr/share/icons/a.png'''
    assert list(rpm_verify(out)) == [('/usr/bin/ls', 'contents changed'), ('/usr/sbin/sshd', 'missing')]


if __name__ == '__main__':
    test_rpm_verify(); print('ok')
