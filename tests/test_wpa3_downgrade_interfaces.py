#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""WPA3 downgrade must not share an interface with airodump."""

import sys
import time
import unittest
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, '..')

from wifite.attack.wpa3 import AttackWPA3SAE
from wifite.config import Configuration
from wifite.model.attack import Attack

pytestmark = pytest.mark.timeout(30)


class TestDowngradeInterfaceSelection(unittest.TestCase):
    def test_secondary_interface_is_used_for_airodump(self):
        with patch.object(Configuration, 'interface', 'wlan0'), \
             patch.object(Configuration, 'interface_secondary', 'wlan1'):
            self.assertEqual(
                AttackWPA3SAE._downgrade_interfaces(), ('wlan0', 'wlan1'))

    def test_without_secondary_airodump_is_disabled(self):
        with patch.object(Configuration, 'interface', 'wlan0'), \
             patch.object(Configuration, 'interface_secondary', None):
            self.assertEqual(
                AttackWPA3SAE._downgrade_interfaces(), ('wlan0', None))

    def test_secondary_equal_to_primary_is_rejected(self):
        with patch.object(Configuration, 'interface', 'wlan0'), \
             patch.object(Configuration, 'interface_secondary', 'wlan0'):
            self.assertEqual(
                AttackWPA3SAE._downgrade_interfaces(), ('wlan0', None))


class TestWaitForTargetTimeout(unittest.TestCase):
    """wait_for_target now accepts a bounded timeout (the loop passes 1s)."""

    def test_honours_explicit_timeout(self):
        attack = Attack(MagicMock())
        airodump = MagicMock()
        airodump.get_targets.return_value = []

        started = time.time()
        with self.assertRaises(Exception):
            attack.wait_for_target(airodump, timeout=0)
        self.assertLess(time.time() - started, 3)

    def test_returns_matching_target(self):
        target = MagicMock(bssid='AA:BB:CC:DD:EE:FF')
        attack = Attack(target)
        match = MagicMock(bssid='AA:BB:CC:DD:EE:FF')
        airodump = MagicMock()
        airodump.get_targets.return_value = [match]

        self.assertIs(attack.wait_for_target(airodump, timeout=1), match)


if __name__ == '__main__':
    unittest.main()