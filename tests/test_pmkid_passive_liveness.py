#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Passive PMKID capture must fail fast when hcxdumptool dies."""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.attack.pmkid_passive import AttackPassivePMKID
from wifite.config import Configuration
from wifite.tools.hcxdumptool import HcxDumpToolPassive

pytestmark = pytest.mark.timeout(30)


class TestPassiveCaptureLiveness(unittest.TestCase):
    def test_run_returns_false_when_capture_exits(self):
        attack = AttackPassivePMKID()

        fake = MagicMock()
        fake.__enter__.return_value = fake
        fake.is_running.return_value = False
        fake.get_failure_reason.return_value = 'failed to get interface index'

        with patch.object(attack, 'validate_dependencies', return_value=True), \
             patch.object(attack, 'display_statistics'), \
             patch.object(attack, 'start_monitoring_thread'), \
             patch.object(attack, 'cleanup') as cleanup, \
             patch('wifite.attack.pmkid_passive.HcxDumpToolPassive',
                   return_value=fake), \
             patch.object(Configuration, 'pmkid_passive_duration', 60), \
             patch.object(Configuration, 'pmkid_passive_interval', 30), \
             patch('wifite.attack.pmkid_passive.Color'):
            self.assertFalse(attack.run())

        cleanup.assert_called_once()

    def test_failure_reason_reads_last_error_line(self):
        with patch('wifite.tools.hcxdumptool.Configuration.initialize'):
            tool = HcxDumpToolPassive(interface='wlan0',
                                      output_file='/tmp/x.pcapng')

        tool.proc = MagicMock()
        tool.proc.get_output.return_value = (
            'debug output',
            'line one\nfailed to get interface index: No such device',
        )

        self.assertEqual(
            tool.get_failure_reason(),
            'failed to get interface index: No such device',
        )

    def test_failure_reason_empty_when_process_missing(self):
        with patch('wifite.tools.hcxdumptool.Configuration.initialize'):
            tool = HcxDumpToolPassive(interface='wlan0',
                                      output_file='/tmp/x.pcapng')
        self.assertEqual(tool.get_failure_reason(), '')


if __name__ == '__main__':
    unittest.main()