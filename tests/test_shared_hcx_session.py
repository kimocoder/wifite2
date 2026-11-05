#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""AttackWPA reuses the capture published by the PMKID session."""

import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, '..')

from wifite.attack.wpa import AttackWPA
from wifite.config import Configuration

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'
ESSID = 'CYBERSPACE'


def make_target():
    target = Mock()
    target.bssid = BSSID
    target.essid = ESSID
    target.essid_known = True
    target.channel = 6
    target.power = 50
    target.wps = 0
    target.wpa_ft = False
    return target


class SharedCaptureReuseTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.capfile = os.path.join(self.tmpdir.name, 'shared.pcapng')
        with open(self.capfile, 'wb') as handle:
            handle.write(b'pcapng-data')

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_valid_shared_capture_is_reused(self):
        attack = AttackWPA(make_target())
        with patch('wifite.util.capture_cache.get',
                   return_value=self.capfile), \
             patch('wifite.attack.wpa.Handshake.has_handshake',
                   return_value=True), \
             patch('wifite.attack.wpa.Airodump',
                   side_effect=AssertionError('airodump must not start')):
            handshake = attack.capture_handshake()

        assert handshake is not None
        assert handshake.capfile == self.capfile

    def test_shared_capture_without_handshake_is_ignored(self):
        attack = AttackWPA(make_target())
        with patch('wifite.util.capture_cache.get',
                   return_value=self.capfile), \
             patch('wifite.attack.wpa.Handshake.has_handshake',
                   return_value=False):
            assert attack._reuse_shared_capture() is None

    def test_no_shared_capture(self):
        attack = AttackWPA(make_target())
        with patch('wifite.util.capture_cache.get', return_value=None):
            assert attack._reuse_shared_capture() is None

    def test_unreadable_shared_capture_is_ignored(self):
        attack = AttackWPA(make_target())
        with patch('wifite.util.capture_cache.get',
                   return_value=self.capfile), \
             patch('wifite.attack.wpa.Handshake.has_handshake',
                   side_effect=ValueError('cannot parse capture')):
            assert attack._reuse_shared_capture() is None


class WpsOnlyGuardTest(unittest.TestCase):
    def test_non_wps_target_is_skipped(self):
        target = make_target()
        target.wps = 0  # WPSState.NONE
        attack = AttackWPA(target)

        with patch.object(Configuration, 'wps_only', True), \
             patch.object(Configuration, 'use_pmkid_only', False), \
             patch.object(AttackWPA, '_get_interface_assignment',
                          side_effect=AssertionError('must skip before setup')):
            assert attack.run() is False

    def test_wps_target_is_not_skipped(self):
        target = make_target()
        target.wps = 1  # WPSState.UNLOCKED
        attack = AttackWPA(target)

        with patch.object(Configuration, 'wps_only', True), \
             patch.object(Configuration, 'use_pmkid_only', False), \
             patch.object(AttackWPA, '_get_interface_assignment',
                          side_effect=RuntimeError('reached setup')):
            with pytest.raises(RuntimeError, match='reached setup'):
                attack.run()


if __name__ == '__main__':
    unittest.main()