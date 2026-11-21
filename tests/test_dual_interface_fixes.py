#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Regression tests for dual-interface cleanup, launcher, and role assignment."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifite.attack.eviltwin import EvilTwin
from wifite.model.interface_info import InterfaceInfo
from wifite.util.interface_assignment import InterfaceAssignmentStrategy
from wifite.util.interface_manager import InterfaceManager, InterfaceState

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_iface(name, phy, tx_power):
    return InterfaceInfo(
        name=name,
        phy=phy,
        driver='mt76x0u',
        chipset='MediaTek',
        mac_address='00:11:22:33:44:55',
        supports_ap_mode=True,
        supports_monitor_mode=True,
        supports_injection=True,
        current_mode='monitor',
        is_up=True,
        is_connected=False,
        tx_power=tx_power,
    )


class TestDeauthRoleUsesStrongerRadio(unittest.TestCase):
    """Deauth range depends on TX power, so the stronger radio must deauth."""

    def test_roles_swapped_when_capture_radio_is_stronger(self):
        strong = make_iface('wlan1', 'phy1', 20)
        weak = make_iface('wlan2', 'phy2', 3)

        with patch('wifite.util.color.Color.pl'):
            assignment = InterfaceAssignmentStrategy.assign_for_wpa([strong, weak])

        self.assertEqual(assignment.primary, 'wlan2')
        self.assertEqual(assignment.secondary, 'wlan1')

    def test_roles_kept_when_power_is_similar(self):
        first = make_iface('wlan1', 'phy1', 18)
        second = make_iface('wlan2', 'phy2', 16)

        with patch('wifite.util.color.Color.pl'):
            assignment = InterfaceAssignmentStrategy.assign_for_wpa([first, second])

        self.assertEqual(assignment.primary, 'wlan1')
        self.assertEqual(assignment.secondary, 'wlan2')


class TestRestoreOrder(unittest.TestCase):
    """Channel restore must happen after the link is brought back up."""

    def _manager_with_state(self):
        manager = InterfaceManager()
        state = InterfaceState(
            name='wlan0',
            original_mode='monitor',
            original_up=True,
            original_mac='AA:BB:CC:DD:EE:01',
            original_channel=6,
            current_mode='managed',
            current_up=True,
            original_ips=[],
            original_ifindex=7,
            original_promisc=False,
            original_allmulti=False,
        )
        state.changed_fields.update({'mode', 'up', 'channel'})
        manager.interface_states['wlan0'] = state
        manager.managed_interfaces['wlan0'] = {'interface': 'wlan0'}
        return manager

    def _restore_recording_calls(self, channel_side_effect):
        manager = self._manager_with_state()
        calls = []

        def record_run(command, *args, **kwargs):
            calls.append(command)
            return True

        with patch.object(manager, '_get_interface_ifindex', return_value=7), \
                patch.object(manager, '_get_interface_mode', return_value='monitor'), \
                patch.object(manager, '_is_interface_up', return_value=True), \
                patch.object(manager, '_get_interface_mac',
                             return_value='AA:BB:CC:DD:EE:01'), \
                patch.object(manager, '_get_interface_channel',
                             side_effect=channel_side_effect), \
                patch.object(manager, '_get_interface_addresses', return_value=[]), \
                patch.object(manager, '_get_interface_flags', return_value=0), \
                patch.object(manager, '_set_link_state', return_value=True), \
                patch.object(manager, '_mode_command', return_value=['true']), \
                patch.object(manager, 'set_interface_up',
                             side_effect=lambda i, u: calls.append('up') or True), \
                patch.object(manager, '_run_checked', side_effect=record_run):
            self.assertTrue(manager.restore_interface('wlan0'))
        return calls

    def test_channel_is_restored_after_link_up(self):
        calls = self._restore_recording_calls(lambda interface: 6)
        channel_index = next(
            i for i, command in enumerate(calls)
            if isinstance(command, list) and 'channel' in command)
        up_index = calls.index('up')
        self.assertGreater(channel_index, up_index)

    def test_channel_restored_when_unreadable_while_down(self):
        # First read (live diff) returns None because the AP left the link
        # down; subsequent reads report the restored channel.
        reads = {'count': 0}

        def channel_side_effect(interface):
            reads['count'] += 1
            return None if reads['count'] == 1 else 6

        calls = self._restore_recording_calls(channel_side_effect)
        self.assertTrue(any(isinstance(c, list) and 'channel' in c for c in calls))


class TestEvilTwinInterfaceSnapshot(unittest.TestCase):
    """The AP interface is snapshotted before mutation and its MAC restored."""

    def setUp(self):
        self.eviltwin = object.__new__(EvilTwin)
        self.eviltwin._original_ap_mac = None
        self.eviltwin.interface_ap = 'wlan1'
        self.eviltwin.interface_deauth = 'wlan2'

    def test_claims_ap_interface_before_bringing_it_down(self):
        calls = []
        manager = Mock()
        manager.claim_interface.side_effect = lambda iface: calls.append('claim') or True

        with patch('wifite.attack.eviltwin.Configuration.get_interface_manager',
                   return_value=manager), \
                patch('wifite.tools.nexmon.Nexmon.has_session', return_value=False), \
                patch('wifite.tools.airmon.Airmon.put_interface_down',
                      side_effect=lambda iface: calls.append('down')), \
                patch('wifite.tools.airmon.Airmon.set_interface_mode', return_value=True), \
                patch('wifite.tools.airmon.Airmon.put_interface_up', return_value=None), \
                patch('wifite.tools.ip.Ip.get_mac',
                      return_value='AA:BB:CC:DD:EE:01'), \
                patch('wifite.attack.eviltwin.log_debug'), \
                patch('wifite.attack.eviltwin.log_info'):
            self.assertTrue(
                EvilTwin._configure_ap_interface(self.eviltwin, 'wlan1'))

        self.assertLess(calls.index('claim'), calls.index('down'))
        self.assertEqual(self.eviltwin._original_ap_mac, 'AA:BB:CC:DD:EE:01')

    def test_restores_recorded_ap_mac(self):
        manager = Mock()
        manager.set_interface_mac.return_value = True
        self.eviltwin._original_ap_mac = 'AA:BB:CC:DD:EE:01'

        with patch('wifite.attack.eviltwin.Configuration.get_interface_manager',
                   return_value=manager), \
                patch('wifite.attack.eviltwin.log_info'):
            self.eviltwin._restore_ap_interface_mac()

        manager.set_interface_mac.assert_called_once_with(
            'wlan1', 'AA:BB:CC:DD:EE:01')


class TestLauncherPrefersItsOwnTree(unittest.TestCase):
    """bin/wifite must import the source tree it lives in, not site-packages."""

    def test_launcher_imports_local_package(self):
        tmpdir = tempfile.mkdtemp()
        try:
            repo = os.path.join(tmpdir, 'repo')
            shadow = os.path.join(tmpdir, 'shadow')
            os.makedirs(os.path.join(repo, 'bin'))
            os.makedirs(os.path.join(repo, 'wifite'))
            os.makedirs(os.path.join(shadow, 'wifite'))

            with open(os.path.join(repo, 'wifite', '__init__.py'), 'w') as fh:
                fh.write('MARKER = "local"\n')
            with open(os.path.join(repo, 'wifite', 'wifite.py'), 'w') as fh:
                fh.write('def main():\n    print("LOCAL-MAIN")\n')
            with open(os.path.join(shadow, 'wifite', '__init__.py'), 'w') as fh:
                fh.write('MARKER = "shadow"\n')
            with open(os.path.join(shadow, 'wifite', 'wifite.py'), 'w') as fh:
                fh.write('def main():\n    print("SHADOW-MAIN")\n')

            shutil.copy(os.path.join(REPO_ROOT, 'bin', 'wifite'),
                        os.path.join(repo, 'bin', 'wifite'))

            env = dict(os.environ)
            env['PYTHONPATH'] = shadow
            result = subprocess.run(
                [sys.executable, os.path.join(repo, 'bin', 'wifite')],
                capture_output=True, text=True, env=env, cwd=tmpdir)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('LOCAL-MAIN', result.stdout)
            self.assertNotIn('SHADOW-MAIN', result.stdout)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()