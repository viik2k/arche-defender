import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import shutil, tempfile, unittest
from pathlib import Path
from unittest import mock
from arche import ransomware
from arche.core import ALERT, WARN, INFO


class Tripwire(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.d, True)
        (self.d / 'Documents').mkdir()
        for k, v in (('HOME', str(self.d)), ('DB', self.d / 'state' / 'canaries.json')):
            p = mock.patch.object(ransomware, k, v); p.start(); self.addCleanup(p.stop)

    def sev(self): return [(s, t) for t, s, _ in ransomware.tripwire()]

    def test_lifecycle(self):
        self.assertEqual(self.sev()[0][0], INFO)                                  # off until installed
        self.assertIn('Tripwires set', ransomware.install())
        canary = self.d / 'Documents' / ransomware.NAME
        self.assertTrue(canary.exists()); self.assertEqual(self.sev(), [])
        self.assertEqual(oct(ransomware.DB.stat().st_mode & 0o777), '0o600')
        canary.write_bytes(b'encrypted')
        self.assertEqual(self.sev()[0][0], ALERT)
        canary.rename(str(canary) + '.lockbit')
        s = self.sev(); self.assertEqual(s[0][0], ALERT); self.assertIn('renamed to', s[0][1])
        os.remove(str(canary) + '.lockbit')
        self.assertEqual(self.sev()[0][0], WARN)                                  # just missing
        ransomware.install(); self.assertIn('Removed 1', ransomware.remove())
        self.assertFalse(canary.exists()); self.assertEqual(self.sev()[0][0], INFO)


if __name__ == '__main__':
    unittest.main()


class Backups(unittest.TestCase):
    def rows(self, found):
        return [(r[1], r[0]) for r in ransomware.backup_rows(found, now=100 * 86400)]

    def test_nothing_or_only_snapshots_warns(self):
        self.assertEqual(self.rows([]), [(1, 'No backup of your files found')])
        self.assertEqual(self.rows([('snapshot', 'snapper home (/home)', None)])[-1], (1, 'No backup of your files found (only same-disk snapshots: snapper home)'))

    def test_backup_age(self):
        self.assertEqual(self.rows([('backup', 'Deja Dup', 95 * 86400)]), [(0, 'Backup: Deja Dup')])
        self.assertEqual(self.rows([('backup', 'Deja Dup', 50 * 86400)]), [(1, 'Backup Deja Dup last ran 50 days ago')])
        self.assertTrue(ransomware.epoch('2026-11-01T10:00:00Z'))
