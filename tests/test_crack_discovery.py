#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Capture discovery for --crack: 4-way, PMKID and SAE names."""

import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

from wifite.config import Configuration
from wifite.util.crack import CrackHelper

pytestmark = pytest.mark.timeout(30)

FILES = [
    'handshake_My_Net_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.cap',
    'sae_handshake_TestNet_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.cap',
    'sae_handshake_TestNet2_11-22-33-44-55-66.cap',
    'pmkid_TestNet_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.22000',
    'notes.txt',
    'handshake_malformed.cap',
]


class TestCaptureDiscovery(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cracked = os.path.join(self.dir, 'cracked.json')
        for name in FILES:
            open(os.path.join(self.dir, name), 'w').close()

        self._patches = [
            patch.object(Configuration, 'wpa_handshake_dir', self.dir),
            patch.object(Configuration, 'cracked_file', self.cracked),
            patch.object(Configuration, 'verbose', 0),
            patch('wifite.util.crack.Process.exists', return_value=True),
            patch('wifite.util.crack.Handshake.divine_bssid_and_essid'),
            patch('wifite.util.crack.Color'),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def _by_name(self, handshakes):
        return {os.path.basename(h['filename']): h for h in handshakes}

    def test_discovers_all_supported_shapes(self):
        self.assertEqual(len(CrackHelper.get_handshakes()), 4)

    def test_essid_with_underscore_is_kept(self):
        found = self._by_name(CrackHelper.get_handshakes())
        hs = found['handshake_My_Net_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.cap']
        self.assertEqual(hs['essid'], 'My_Net')
        self.assertEqual(hs['bssid'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(hs['type'], '4-WAY')

    def test_sae_capture_is_discovered(self):
        found = self._by_name(CrackHelper.get_handshakes())
        hs = found['sae_handshake_TestNet_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.cap']
        self.assertEqual(hs['type'], 'SAE')
        self.assertEqual(hs['essid'], 'TestNet')
        self.assertEqual(hs['date'], '2026-01-01 00:00:00')

    def test_sae_without_date_uses_mtime(self):
        found = self._by_name(CrackHelper.get_handshakes())
        hs = found['sae_handshake_TestNet2_11-22-33-44-55-66.cap']
        self.assertEqual(hs['type'], 'SAE')
        self.assertTrue(hs['date'])

    def test_pmkid_is_discovered(self):
        found = self._by_name(CrackHelper.get_handshakes())
        hs = found['pmkid_TestNet_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.22000']
        self.assertEqual(hs['type'], 'PMKID')

    def test_pmkid_skipped_without_hashcat(self):
        with patch('wifite.util.crack.Process.exists',
                   side_effect=lambda name: name != 'hashcat'):
            found = self._by_name(CrackHelper.get_handshakes())
        self.assertNotIn(
            'pmkid_TestNet_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.22000', found)

    def test_corrupt_cracked_file_does_not_abort_discovery(self):
        with open(self.cracked, 'w') as f:
            f.write('{not valid json')
        self.assertFalse(CrackHelper.is_cracked('anything.cap'))
        self.assertEqual(len(CrackHelper.get_handshakes()), 4)


class TestMissingToolGuard(unittest.TestCase):

    def test_pmkid_and_sae_need_hashcat(self):
        self.assertIsNotNone(
            CrackHelper._skip_reason('PMKID', {'hashcat'}))
        self.assertIsNotNone(
            CrackHelper._skip_reason('SAE', {'hashcat'}))

    def test_four_way_does_not_need_hashcat(self):
        self.assertIsNone(CrackHelper._skip_reason('4-WAY', {'hashcat'}))
        self.assertIsNone(CrackHelper._skip_reason('PMKID', set()))


if __name__ == '__main__':
    unittest.main()