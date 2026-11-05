#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""MAC randomization must not fight hcxdumptool's own MAC handling."""

import sys
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration

pytestmark = pytest.mark.timeout(30)


class TestMacchangerSkip(unittest.TestCase):
    def _run(self, **flags):
        from contextlib import ExitStack

        values = {
            'use_hcxdump': False,
            'pmkid_passive': False,
            'use_pmkid_only': False,
            'wpa3_only': False,
            'wpa3_force_sae': False,
            'wpa3_no_downgrade': False,
        }
        values.update(flags)

        with ExitStack() as stack:
            stack.enter_context(patch.object(Configuration, 'interface', None))
            stack.enter_context(patch.object(Configuration, 'random_mac', True))
            stack.enter_context(patch.object(Configuration, 'random_mac_vendor', False))
            for key, value in values.items():
                stack.enter_context(patch.object(Configuration, key, value))

            airmon = stack.enter_context(patch('wifite.tools.airmon.Airmon'))
            macchanger = stack.enter_context(patch('wifite.config.Macchanger'))
            stack.enter_context(patch('wifite.config.Color'))

            airmon.ask.return_value = 'wlan0'
            Configuration.get_monitor_mode_interface()

        return macchanger

    def test_skips_macchanger_with_hcxdump_capture(self):
        macchanger = self._run(use_hcxdump=True)
        macchanger.random.assert_not_called()

    def test_skips_macchanger_with_passive_pmkid(self):
        macchanger = self._run(pmkid_passive=True)
        macchanger.random.assert_not_called()

    def test_skips_macchanger_with_pmkid_only(self):
        macchanger = self._run(use_pmkid_only=True)
        macchanger.random.assert_not_called()

    def test_skips_macchanger_for_forced_sae(self):
        macchanger = self._run(wpa3_force_sae=True)
        macchanger.random.assert_not_called()

    def test_still_randomizes_for_airodump_captures(self):
        macchanger = self._run()
        macchanger.random.assert_called_once()


if __name__ == '__main__':
    unittest.main()