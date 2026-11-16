# Run: python3 tests/test_integrity.py (or pytest)
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from arche.integrity import rpm_verify, pacman_verify


def test_rpm_verify():
    out = '''..?......    /usr/bin/sudo
S.5....T.    /usr/bin/ls
S.5....T.  c /etc/sudoers
missing     /usr/sbin/sshd
missing     /var/db/sudo/lectured (Permission denied)
.......T.  d /usr/share/doc/x
..5......    /usr/share/icons/a.png'''
    assert list(rpm_verify(out)) == [('/usr/bin/ls', 'contents changed'), ('/usr/sbin/sshd', 'missing')]


def test_dpkg_verify():   # dpkg --verify prints the rpm format; usrmerge paths may be /bin/...
    out = '??5??????   /bin/ls\n??5?????? c /etc/ssh/sshd_config\n??5??????   /usr/share/man/man1/ls.1.gz'
    assert list(rpm_verify(out)) == [('/bin/ls', 'contents changed')]


def test_pacman_verify():
    out = """warning: coreutils: /usr/bin/ls (SHA256 checksum mismatch)
warning: coreutils: /usr/bin/ls (Size mismatch)
warning: coreutils: /usr/bin/cat (Modification time mismatch)
warning: openssh: /usr/bin/sshd (No such file or directory)
warning: sudo: /etc/sudoers (SHA256 checksum mismatch)
warning: filesystem: /usr/lib/x (Permission denied)
coreutils: 123 total files, 2 altered files"""
    assert list(pacman_verify(out)) == [('/usr/bin/ls', 'contents changed'), ('/usr/bin/sshd', 'missing')]


if __name__ == '__main__':
    test_rpm_verify(); test_dpkg_verify(); test_pacman_verify(); print('ok')
