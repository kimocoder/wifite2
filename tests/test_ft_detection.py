#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""WPA-FT (802.11r) detection and attack selection."""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.attack.wpa import AttackWPA
from wifite.config import Configuration
from wifite.util.wpa3 import WPA3Detector

pytestmark = pytest.mark.timeout(30)

BSSID = 'AA:BB:CC:DD:EE:FF'


class TestFtAkmParsing(unittest.TestCase):
    def _parse(self, akm_types):
        stdout = '\t'.join([BSSID, '0', '0', '19', akm_types]) + '\n'
        with patch('wifite.tools.tshark.Tshark.exists', return_value=True), \
             patch('wifite.util.process.Process') as process:
            process.return_value.get_output.return_value = (stdout, '')
            process.return_value.poll.return_value = 0
            return WPA3Detector.parse_capture_batch('/tmp/cap.pcapng')

    def test_ft_psk_akm_marks_target(self):
        result = self._parse('4')
        self.assertTrue(result[BSSID]['ft'])

    def test_ft_8021x_akm_marks_target(self):
        result = self._parse('3')
        self.assertTrue(result[BSSID]['ft'])

    def test_plain_psk_is_not_ft(self):
        result = self._parse('2')
        self.assertFalse(result[BSSID].get('ft', False))


class TestFtTargetModel(unittest.TestCase):
    def _target(self):
        target = MagicMock()
        target.bssid = BSSID
        target.full_encryption_string = 'WPA2'
        target.full_authentication_string = 'PSK'
        target.primary_encryption = 'WPA2'
        target.primary_authentication = 'PSK'
        target.wpa3_info = None
        target.wpa_ft = False
        return target

    def test_detection_sets_wpa_ft_flag(self):
        target = self._target()
        parsed = {'pmf_status': None, 'sae_groups': [], 'ft': True}
        with patch.object(WPA3Detector, '_parse_rsn_from_capture',
                          return_value=parsed), \
             patch('wifite.util.wpa3.os.path.isfile', return_value=True):
            info = WPA3Detector.detect_wpa3_capability(
                target, use_cache=False, capfile='/tmp/cap.pcapng')

        self.assertTrue(target.wpa_ft)
        self.assertTrue(info['wpa_ft'])

    def test_detection_reports_no_ft(self):
        target = self._target()
        parsed = {'pmf_status': None, 'sae_groups': [], 'ft': False}
        with patch.object(WPA3Detector, '_parse_rsn_from_capture',
                          return_value=parsed), \
             patch('wifite.util.wpa3.os.path.isfile', return_value=True):
            info = WPA3Detector.detect_wpa3_capability(
                target, use_cache=False, capfile='/tmp/cap.pcapng')

        self.assertFalse(target.wpa_ft)
        self.assertFalse(info['wpa_ft'])


class TestFtAttackSelection(unittest.TestCase):
    def test_ft_target_uses_hcxdumptool_capture(self):
        attack = AttackWPA.__new__(AttackWPA)
        attack.target = MagicMock(wpa_ft=True)
        attack.view = None

        with patch.object(Configuration, 'use_hcxdump', False), \
             patch('wifite.tools.hcxdumptool.HcxDumpTool.exists',
                   return_value=True), \
             patch('wifite.tools.hcxdumptool.HcxDumpTool.check_minimum_version',
                   return_value=True), \
             patch.object(attack, '_capture_handshake_single_hcxdump',
                          return_value='handshake') as capture, \
             patch('wifite.attack.wpa.Color'):
            result = attack.capture_handshake()

        self.assertEqual(result, 'handshake')
        capture.assert_called_once()


if __name__ == '__main__':
    unittest.main()