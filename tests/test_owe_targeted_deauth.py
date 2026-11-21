#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""OWE downgrade should deauth discovered clients, not just broadcast."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from wifite.attack.owe import AttackOWE
from wifite.config import Configuration

pytestmark = pytest.mark.timeout(30)


class FakeTimer:
    """Down-window timer that reports ended on the second check."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.calls = 0

    def ended(self):
        self.calls += 1
        if self.seconds >= 60:
            return self.calls > 1
        return True

    def __str__(self):
        return '0:00'


class TestOweTargetedDeauth(unittest.TestCase):

    def test_downgrade_deauths_each_discovered_client(self):
        attack = AttackOWE.__new__(AttackOWE)
        attack.target = SimpleNamespace(
            channel=6, bssid='11:22:33:44:55:66', essid='OWE-Net')
        attack.view = None
        attack.success = False

        client = SimpleNamespace(station='AA:BB:CC:DD:EE:FF')
        airodump_target = SimpleNamespace(clients=[client])

        with patch('wifite.attack.owe.Airodump') as airodump_cls, \
                patch('wifite.attack.owe.Aireplay') as aireplay, \
                patch('wifite.attack.owe.Timer', FakeTimer), \
                patch('wifite.attack.owe.time.sleep'), \
                patch('wifite.attack.owe.Color'), \
                patch.object(AttackOWE, 'wait_for_target',
                             return_value=airodump_target), \
                patch('wifite.attack.owe.log_info'), \
                patch('wifite.attack.owe.log_debug'):
            airodump_cls.return_value.__enter__.return_value = MagicMock()
            airodump_cls.return_value.__exit__.return_value = False

            self.assertTrue(attack._execute_transition_downgrade())

        aireplay.deauth.assert_called_with(
            '11:22:33:44:55:66',
            client_mac='AA:BB:CC:DD:EE:FF',
            num_deauths=Configuration.num_deauths,
        )

    def test_downgrade_falls_back_to_broadcast_without_clients(self):
        attack = AttackOWE.__new__(AttackOWE)
        attack.target = SimpleNamespace(
            channel=6, bssid='11:22:33:44:55:66', essid='OWE-Net')
        attack.view = None
        attack.success = False

        airodump_target = SimpleNamespace(clients=[])

        with patch('wifite.attack.owe.Airodump') as airodump_cls, \
                patch('wifite.attack.owe.Aireplay') as aireplay, \
                patch('wifite.attack.owe.Timer', FakeTimer), \
                patch('wifite.attack.owe.time.sleep'), \
                patch('wifite.attack.owe.Color'), \
                patch.object(AttackOWE, 'wait_for_target',
                             return_value=airodump_target), \
                patch('wifite.attack.owe.log_info'), \
                patch('wifite.attack.owe.log_debug'):
            airodump_cls.return_value.__enter__.return_value = MagicMock()
            airodump_cls.return_value.__exit__.return_value = False

            self.assertTrue(attack._execute_transition_downgrade())

        aireplay.deauth.assert_called_with(
            '11:22:33:44:55:66',
            num_deauths=Configuration.num_deauths,
        )


if __name__ == '__main__':
    unittest.main()