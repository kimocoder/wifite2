#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""WPS first-pass behaviour: no bogus '0 of 0 targets' scan."""

import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.model.target import WPSState
from wifite.tools.airodump import Airodump
from wifite.tools.wash import Wash

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'


class AirodumpAnalyzeTest(unittest.TestCase):
    def _airodump(self):
        airodump = Airodump.__new__(Airodump)
        airodump._capture_analysis_signature = None
        airodump._wps_capture_cache = {}
        airodump._wpa3_capture_cache = {}
        airodump.skip_wps = False
        return airodump

    def test_no_targets_skips_analysis(self):
        airodump = self._airodump()
        with patch('wifite.tools.airodump.Tshark.get_wps_status_map') as wps, \
             patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch') as wpa3:
            airodump._analyze_capture('/tmp/does-not-matter.cap', [])

        wps.assert_not_called()
        wpa3.assert_not_called()
        assert airodump._capture_analysis_signature is None

    def _analyze(self, size):
        target = SimpleNamespace(bssid=BSSID, wps=WPSState.UNKNOWN)
        airodump = self._airodump()

        with tempfile.NamedTemporaryFile(suffix='.cap') as handle:
            handle.write(b'\x00' * size)
            handle.flush()
            with patch('wifite.tools.airodump.Tshark.exists',
                       return_value=True), \
                 patch('wifite.tools.airodump.Tshark.get_wps_status_map',
                       return_value={}), \
                 patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch',
                       return_value={}), \
                 patch.object(Airodump, 'detect_wpa3_capabilities'):
                airodump._analyze_capture(handle.name, [target])

        return airodump, target

    def test_header_only_capture_keeps_previous_state(self):
        airodump, target = self._analyze(100)

        assert target.wps == WPSState.UNKNOWN
        assert airodump._capture_analysis_signature is None

    def test_populated_capture_marks_missing_targets_none(self):
        airodump, target = self._analyze(Airodump.MIN_CAPTURE_BYTES + 1)

        assert target.wps == WPSState.NONE
        assert airodump._capture_analysis_signature is not None


class WashEmptyTargetsTest(unittest.TestCase):
    def test_no_scan_when_target_list_is_empty(self):
        with patch.object(Wash, 'exists', return_value=True), \
             patch('wifite.tools.wash.Process') as process:
            Wash.check_for_wps_and_update_targets('capture.cap', [])

        process.assert_not_called()


if __name__ == '__main__':
    unittest.main()