import unittest
from unittest.mock import patch

from wifite.config import Configuration
from wifite.model.interface_info import InterfaceInfo
from wifite.wifite import Wifite


def make_iface(name, phy, mode='managed'):
    return InterfaceInfo(
        name=name,
        phy=phy,
        driver='brcmfmac',
        chipset='Broadcom 43455',
        mac_address='00:11:22:33:44:55',
        supports_ap_mode=True,
        supports_monitor_mode=True,
        supports_injection=True,
        current_mode=mode,
        is_up=(mode != 'monitor'),
        is_connected=False,
    )


class TestDualInterfacePhyDedup(unittest.TestCase):
    """A station and its monitor share one radio and must not count as two
    monitor-capable interfaces for dual interface mode."""

    def setUp(self):
        self.app = Wifite.__new__(Wifite)
        self.app.available_interfaces = []
        self.app.interface_assignment = None

    def _validate(self, interfaces):
        self.app.available_interfaces = interfaces
        with patch('wifite.util.interface_manager.InterfaceManager'
                   '.check_monitor_mode_support', return_value=True), \
                patch.object(Configuration, 'verbose', 0), \
                patch('wifite.wifite.Color.pl'):
            return self.app._validate_and_prepare_dual_interfaces()

    def test_station_and_its_monitor_count_as_one_radio(self):
        station = make_iface('wlan0', 'phy1', mode='managed')
        monitor = make_iface('wlan0mon', 'phy1', mode='monitor')

        self.assertFalse(self._validate([station, monitor]))
        self.assertEqual([i.name for i in self.app.available_interfaces],
                         ['wlan0mon'])

    def test_dedup_prefers_monitor_regardless_of_order(self):
        for interfaces in (
            [make_iface('wlan0', 'phy1', mode='managed'),
             make_iface('wlan0mon', 'phy1', mode='monitor')],
            [make_iface('wlan0mon', 'phy1', mode='monitor'),
             make_iface('wlan0', 'phy1', mode='managed')],
        ):
            with self.subTest(order=[i.name for i in interfaces]):
                self.app.available_interfaces = []
                self.assertFalse(self._validate(interfaces))
                self.assertEqual([i.name for i in self.app.available_interfaces],
                                 ['wlan0mon'])

    def test_distinct_phys_are_both_kept(self):
        monitor = make_iface('wlan0mon', 'phy1', mode='monitor')
        other = make_iface('wlan1', 'phy2', mode='managed')

        self.assertTrue(self._validate([monitor, other]))
        self.assertEqual(
            sorted(i.name for i in self.app.available_interfaces),
            ['wlan0mon', 'wlan1'])

    def test_three_candidates_on_two_phys_keep_one_per_phy(self):
        station = make_iface('wlan0', 'phy1', mode='managed')
        monitor = make_iface('wlan0mon', 'phy1', mode='monitor')
        other = make_iface('wlan1', 'phy2', mode='managed')

        self.assertTrue(self._validate([station, monitor, other]))
        self.assertEqual(
            sorted(i.name for i in self.app.available_interfaces),
            ['wlan0mon', 'wlan1'])

    def test_non_monitor_pair_on_same_phy_keeps_first(self):
        first = make_iface('wlan0', 'phy1', mode='managed')
        second = make_iface('wlan0mon', 'phy1', mode='managed')

        self.assertFalse(self._validate([first, second]))
        self.assertEqual([i.name for i in self.app.available_interfaces],
                         ['wlan0'])


if __name__ == '__main__':
    unittest.main()
