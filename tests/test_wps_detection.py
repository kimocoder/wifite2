#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""WPS detection parsing (wash + tshark) with fixture output.

Live WPS coverage needs an AP with WPS enabled; these tests exercise the
parsers that turn scan output into WPSState values.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.model.target import WPSState
from wifite.tools.tshark import Tshark
from wifite.tools.wash import Wash

pytestmark = pytest.mark.timeout(30)

BSSID_UNLOCKED = 'A4:2B:8C:16:6B:3A'
BSSID_LOCKED = '11:22:33:44:55:66'
BSSID_NONE = 'AA:BB:CC:DD:EE:FF'


class FakeTarget:
    def __init__(self, bssid):
        self.bssid = bssid
        self.wps = WPSState.UNKNOWN


class WashParsingTest(unittest.TestCase):
    def test_unlocked_locked_and_absent(self):
        output = '\n'.join([
            '{"bssid": "%s", "wps_locked": false}' % BSSID_UNLOCKED,
            '{"bssid": "%s", "wps_locked": true}' % BSSID_LOCKED,
            'not json',
            '{"bssid": "%s"}' % BSSID_NONE,
        ])

        fake = MagicMock()
        fake.return_value.wait.return_value = 0
        fake.return_value.stdout.return_value = output

        targets = [FakeTarget(BSSID_UNLOCKED), FakeTarget(BSSID_LOCKED),
                   FakeTarget(BSSID_NONE)]

        with patch.object(Wash, 'exists', return_value=True), \
             patch('wifite.tools.wash.Process', fake):
            Wash.check_for_wps_and_update_targets('capture.cap', targets)

        assert targets[0].wps == WPSState.UNLOCKED
        assert targets[1].wps == WPSState.LOCKED
        assert targets[2].wps == WPSState.NONE

    def test_missing_wash_is_a_noop(self):
        targets = [FakeTarget(BSSID_UNLOCKED)]
        with patch.object(Wash, 'exists', return_value=False):
            Wash.check_for_wps_and_update_targets('capture.cap', targets)
        assert targets[0].wps == WPSState.UNKNOWN


class TsharkWpsParsingTest(unittest.TestCase):
    def _run(self, output):
        fake = MagicMock()
        fake.return_value.get_output.return_value = (output, '')
        fake.return_value.poll.return_value = 0
        with patch.object(Tshark, 'exists', return_value=True), \
             patch('wifite.tools.tshark.Process', fake):
            return Tshark.get_wps_status_map('capture.cap')

    def test_locked_and_unlocked_rows(self):
        output = '\n'.join([
            '%s,0x00' % BSSID_UNLOCKED,
            '%s,0x01' % BSSID_LOCKED,
            'garbage',
        ])

        status = self._run(output)

        assert status[BSSID_UNLOCKED] == WPSState.UNLOCKED
        assert status[BSSID_LOCKED] == WPSState.LOCKED
        assert len(status) == 2

    def test_empty_output(self):
        assert self._run('') == {}


if __name__ == '__main__':
    unittest.main()