#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""hcxdumptool lifecycle: version floors, pairing, radio handover, readiness."""

import sys
import unittest
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration
from wifite.tools.dependency import Dependency
from wifite.tools.hcxdumptool import (
    HcxDumpTool,
    HcxDumpToolPassive,
    HcxPcapngTool,
)
from wifite.util.system_check import (
    CheckStatus,
    InterfaceCheckResult,
    SystemCheck,
    ToolCheckResult,
)

pytestmark = pytest.mark.timeout(30)


class TestVersionFloors(unittest.TestCase):
    """The wrappers emit hcxdumptool 7+ syntax, so the floor is 7.0.0."""

    def test_minimum_versions_match_7x_syntax(self):
        self.assertEqual(Dependency.MINIMUM_VERSIONS['hcxdumptool'], '7.0.0')
        self.assertEqual(Dependency.MINIMUM_VERSIONS['hcxpcapngtool'], '7.0.0')

    def test_dependency_minimum_version_lookup(self):
        self.assertEqual(HcxDumpTool.get_minimum_version(), '7.0.0')
        self.assertEqual(HcxPcapngTool.get_minimum_version(), '7.0.0')


class TestToolPairing(unittest.TestCase):
    """hcxdumptool and hcxpcapngtool must come from the same suite release."""

    @patch('wifite.tools.hcxdumptool.HcxPcapngTool.check_version', return_value='8.0.0')
    @patch('wifite.tools.hcxdumptool.HcxDumpTool.check_version', return_value='8.0.0')
    def test_matching_versions(self, mock_dump, mock_cap):
        self.assertEqual(HcxDumpTool.check_tool_pairing(), (True, None))

    @patch('wifite.tools.hcxdumptool.HcxPcapngTool.check_version', return_value='7.1.0')
    @patch('wifite.tools.hcxdumptool.HcxDumpTool.check_version', return_value='8.0.0')
    def test_mismatched_versions_report_both(self, mock_dump, mock_cap):
        paired, message = HcxDumpTool.check_tool_pairing()
        self.assertFalse(paired)
        self.assertIn('8.0.0', message)
        self.assertIn('7.1.0', message)

    @patch('wifite.tools.hcxdumptool.HcxPcapngTool.check_version', return_value='8.0.0-5-gabc')
    @patch('wifite.tools.hcxdumptool.HcxDumpTool.check_version', return_value='8.0.0-1-gdef')
    def test_patch_suffixes_are_ignored(self, mock_dump, mock_cap):
        self.assertEqual(HcxDumpTool.check_tool_pairing(), (True, None))

    @patch('wifite.tools.hcxdumptool.HcxPcapngTool.check_version', return_value=None)
    @patch('wifite.tools.hcxdumptool.HcxDumpTool.check_version', return_value='8.0.0')
    def test_unknown_version_is_not_an_error(self, mock_dump, mock_cap):
        self.assertEqual(HcxDumpTool.check_tool_pairing(), (True, None))


class TestMonitorHandover(unittest.TestCase):
    """hcxdumptool 7+ owns monitor mode; wifite must not pre-arm it."""

    def setUp(self):
        Configuration.interface = None
        self.manager = MagicMock()
        self.manager.get_interface_state.return_value = {'mode': 'monitor'}
        self.manager.is_managed.return_value = True
        self.manager.set_interface_mode.return_value = True

    def _enter(self, cls=HcxDumpTool, **kwargs):
        with patch('wifite.tools.hcxdumptool.Configuration.initialize'), \
             patch('wifite.tools.hcxdumptool.Configuration.get_interface_manager',
                   return_value=self.manager), \
             patch('wifite.tools.hcxdumptool.HcxDumpTool.check_version',
                   return_value='8.0.0'), \
             patch('wifite.tools.hcxdumptool.Process') as mock_process, \
             patch('wifite.tools.hcxdumptool.time.sleep'):
            instance = mock_process.return_value
            instance.pid.pid = 12345
            instance.poll.return_value = 0  # already exited, skip SIGTERM path

            tool = cls(interface='wlan0', output_file='/tmp/x.pcapng', **kwargs)
            with tool:
                command = mock_process.call_args[0][0]
        return tool, command

    def test_handover_restores_monitor_after_exit(self):
        tool, command = self._enter(manage_interface=True)

        self.assertEqual(
            self.manager.set_interface_mode.call_args_list,
            [call('wlan0', 'managed'), call('wlan0', 'monitor')],
        )
        self.assertEqual(command[0], 'hcxdumptool')

    def test_no_handover_by_default(self):
        self._enter()
        self.manager.set_interface_mode.assert_not_called()

    @patch('wifite.tools.hcxdumptool.HcxDumpTool.check_version',
           return_value='6.9.0')
    def test_no_handover_before_hcxdumptool_7(self, mock_version):
        with patch('wifite.tools.hcxdumptool.Configuration.initialize'), \
             patch('wifite.tools.hcxdumptool.Configuration.get_interface_manager',
                   return_value=self.manager), \
             patch('wifite.tools.hcxdumptool.Process') as mock_process, \
             patch('wifite.tools.hcxdumptool.time.sleep'):
            instance = mock_process.return_value
            instance.poll.return_value = 0
            HcxDumpTool(interface='wlan0', output_file='/tmp/x.pcapng',
                        manage_interface=True).__enter__()

        self.manager.set_interface_mode.assert_not_called()

    def test_foreign_monitor_interface_is_left_alone(self):
        self.manager.is_managed.return_value = False
        self._enter(manage_interface=True)
        self.manager.set_interface_mode.assert_not_called()

    def test_passive_wrapper_hands_over_the_radio(self):
        with patch('wifite.tools.hcxdumptool.Configuration.initialize'), \
             patch('wifite.tools.hcxdumptool.Configuration.get_interface_manager',
                   return_value=self.manager), \
             patch('wifite.tools.hcxdumptool.HcxDumpTool.check_version',
                   return_value='8.0.0'), \
             patch('wifite.tools.hcxdumptool.Process') as mock_process, \
             patch('wifite.tools.hcxdumptool.time.sleep'):
            instance = mock_process.return_value
            instance.poll.return_value = 0

            with HcxDumpToolPassive(interface='wlan0',
                                    output_file='/tmp/p.pcapng'):
                pass

        self.assertEqual(
            self.manager.set_interface_mode.call_args_list,
            [call('wlan0', 'managed'), call('wlan0', 'monitor')],
        )


class TestReadinessVersionGates(unittest.TestCase):
    def _checker(self, tools):
        checker = SystemCheck()
        checker.interface_results = [
            InterfaceCheckResult(name='wlan0', supports_monitor=True,
                                 supports_ap=True, supports_injection=True),
        ]
        checker.tool_results = tools
        return checker

    @staticmethod
    def _tool(name, version, category='cracking'):
        return ToolCheckResult(name=name, found=True, version=version,
                               version_ok=True, category=category)

    def test_ft_ready_needs_hashcat_8(self):
        checker = self._checker([
            self._tool('aircrack-ng', '1.7', 'core'),
            self._tool('hashcat', '7.1.2'),
            self._tool('hcxdumptool', '8.0.0', 'wpa3'),
            self._tool('hcxpcapngtool', '8.0.0', 'wpa3'),
        ])
        readiness = checker.assess_attack_readiness()
        self.assertEqual(readiness['WPA-FT (802.11r)'], CheckStatus.WARN)

    def test_ft_passes_with_hashcat_8(self):
        checker = self._checker([
            self._tool('hashcat', '8.0.0'),
        ])
        readiness = checker.assess_attack_readiness()
        self.assertEqual(readiness['WPA-FT (802.11r)'], CheckStatus.PASS)

    def test_ft_fails_without_hashcat(self):
        checker = self._checker([
            self._tool('aircrack-ng', '1.7', 'core'),
        ])
        readiness = checker.assess_attack_readiness()
        self.assertEqual(readiness['WPA-FT (802.11r)'], CheckStatus.FAIL)

    def test_pmkid_crack_needs_a_cracker(self):
        checker = self._checker([
            self._tool('hcxdumptool', '8.0.0', 'wpa3'),
        ])
        readiness = checker.assess_attack_readiness()
        self.assertEqual(readiness['PMKID Capture'], CheckStatus.PASS)
        self.assertEqual(readiness['PMKID Crack'], CheckStatus.FAIL)

    def test_wpa3_sae_warns_on_mismatched_hcxtools(self):
        checker = self._checker([
            self._tool('hcxdumptool', '8.0.0', 'wpa3'),
            self._tool('hcxpcapngtool', '7.1.0', 'wpa3'),
        ])
        readiness = checker.assess_attack_readiness()
        self.assertEqual(readiness['WPA3/SAE'], CheckStatus.WARN)


if __name__ == '__main__':
    unittest.main()