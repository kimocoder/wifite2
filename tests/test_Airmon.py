#!/usr/bin/env python
# -*- coding: utf-8 -*-
import subprocess
import sys
import unittest
from unittest.mock import patch

from wifite.tools.airmon import Airmon, AirmonIface
from wifite.util.errors import WifiteError

sys.path.insert(0, '..')


class TestAirmon(unittest.TestCase):
    def test_airmon_start(self):
        # From https://github.com/derv82/wifite2/issues/67
        stdout = ('\n'
                  'PHY    Interface    Driver        Chipset\n'
                  '\n'
                  'phy0    wlan0        iwlwifi        Intel Corporation Centrino Ultimate-N 6300 (rev 3e)\n'
                  '\n'
                  '        (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n'
                  '        (mac80211 station mode vif disabled for [phy0]wlan0)\n')
        mon_iface = Airmon._parse_airmon_start(stdout)
        assert mon_iface == 'wlan0mon', f'Expected monitor-mode interface to be "wlan0mon" but got "{mon_iface}"'


class TestRequireInterface(unittest.TestCase):
    def test_existing_netdev_passes(self):
        with patch('wifite.tools.airmon.os.path.isdir', return_value=True), \
                patch('wifite.tools.airmon.Process.run_simple') as run:
            Airmon.require_interface('wlan1')
        run.assert_not_called()

    def test_missing_netdev_names_available_interfaces(self):
        available = [AirmonIface('phy0', 'wlp4s0', 'iwlwifi', 'Intel'),
                     AirmonIface('phy1', 'wlx00c0caab4816', 'mt76x0u', 'MediaTek')]
        missing = subprocess.CompletedProcess(['ip'], 1, '', 'Device does not exist')
        with patch('wifite.tools.airmon.os.path.isdir', return_value=False), \
                patch('wifite.tools.airmon.Process.run_simple', return_value=missing), \
                patch.object(Airmon, 'get_interfaces', return_value=available), \
                patch('wifite.tools.airmon.Color'):
            with self.assertRaises(WifiteError) as raised:
                Airmon.require_interface('wlan1')
        self.assertIn('wlan1', str(raised.exception))

    def test_unverifiable_environment_does_not_block(self):
        with patch('wifite.tools.airmon.os.path.isdir', return_value=False), \
                patch('wifite.tools.airmon.Process.run_simple',
                      side_effect=FileNotFoundError('ip')):
            Airmon.require_interface('wlan1')
