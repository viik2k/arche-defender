import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))   # python3 tests/<file>.py
import unittest
from arche import updates
from arche.core import INFO, WARN


class Kernels(unittest.TestCase):
    def test_flavour(self):
        inst = ['7.3.4-201.nobara.fc44.x86_64', '7.3.10-200.nobara.fc44.x86_64', '7.4.1-201.eac.nobara.fc44.x86_64']
        self.assertEqual(updates.newest_same_flavor(inst[0], inst), inst[1])        # 10 > 4, natural order
        self.assertEqual(updates.newest_same_flavor(inst[2], inst), inst[2])        # eac only compares with eac
        self.assertEqual(updates.newest_same_flavor('6.1.0', []), '6.1.0')


class Hsi(unittest.TestCase):
    def test_levels(self):
        ok, bad = ['success'], []
        a = [{'HsiLevel': 1, 'Flags': ok}, {'HsiLevel': 1, 'Flags': ok}, {'HsiLevel': 2, 'Flags': bad}, {'HsiLevel': 3, 'Flags': ok}]
        self.assertEqual(updates.hsi(a), 'HSI:1')
        self.assertEqual(updates.hsi(a + [{'Flags': bad}]), 'HSI:1!')               # runtime issue
        self.assertEqual(updates.hsi([{'HsiLevel': 1, 'Flags': bad}]), 'HSI:0')



class Sources(unittest.TestCase):
    def test_dnf_repos(self):
        repos = [{'id': 'fedora', 'is_enabled': True, 'metalink': 'https://mirrors.fedoraproject.org/metalink?repo=x', 'pkg_gpgcheck': True},
                 {'id': 'sketchy', 'is_enabled': True, 'base_url': ['http://repo.example/x'], 'pkg_gpgcheck': False, 'repo_file_path': '/etc/yum.repos.d/s.repo'},
                 {'id': 'plain', 'base_url': ['http://repo.example/y'], 'pkg_gpgcheck': True},
                 {'id': 'off', 'is_enabled': False, 'pkg_gpgcheck': False}]
        r = [(t, s) for t, s, _ in updates.dnf_repo_rows(repos)]
        self.assertEqual(r, [('Package source: fedora (mirrors.fedoraproject.org)', INFO),
                             ('Packages from repo sketchy (repo.example) are installed without a signature check', WARN),
                             ('Repo plain is fetched over plain http (repo.example); its packages are still signature-checked', INFO)])


if __name__ == '__main__':
    unittest.main()
