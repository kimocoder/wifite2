#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Deauth must never run on the interface hcxdumptool owns."""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.attack.wpa import AttackWPA
from wifite.attack.wpa3 import AttackWPA3SAE
from wifite.config import Configuration

pytestmark = pytest.mark.timeout(30)


class _InlineThread:
    def __init__(self, target=None, args=(), **kwargs):
        self._target = target
        self._args = args

    def start(self):
        self._target(*self._args)

    def join(self):
        pass


class TestParallelDeauthInterface(unittest.TestCase):
    def setUp(self):
        self.attack = AttackWPA.__new__(AttackWPA)
        self.attack.capture_interface = 'wlan0'
        self.attack.deauth_interface = 'wlan1'
        self.attack._capture_owned_by_hcxdump = True
        self.attack.clients = []
        self.attack.view = None
        self.target = MagicMock(bssid='AA:BB:CC:DD:EE:FF')

    def _deauth(self):
        with patch.object(Configuration, 'no_deauth', False), \
             patch('wifite.attack.wpa.Aireplay.deauth') as deauth, \
             patch('threading.Thread', _InlineThread), \
             patch('wifite.attack.wpa.Color'):
            self.attack._deauth_parallel(self.target)
        return {call.kwargs.get('interface')
                for call in deauth.call_args_list}

    def test_deauth_skips_capture_interface(self):
        self.assertEqual(self._deauth(), {'wlan1'})

    def test_airodump_mode_keeps_both_interfaces(self):
        self.attack._capture_owned_by_hcxdump = False
        self.assertEqual(self._deauth(), {'wlan0', 'wlan1'})


class TestDowngradeDeauthOwnership(unittest.TestCase):
    def test_single_radio_defers_deauth_to_hcxdumptool(self):
        self.assertTrue(AttackWPA3SAE._downgrade_capture_deauth(None))

    def test_secondary_radio_allows_external_deauth(self):
        self.assertFalse(AttackWPA3SAE._downgrade_capture_deauth('wlan1'))


if __name__ == '__main__':
    unittest.main()