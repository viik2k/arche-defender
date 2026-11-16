import unittest
from arche import updates


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


if __name__ == '__main__':
    unittest.main()
