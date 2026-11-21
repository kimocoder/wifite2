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

FOUR_WAY = ('handshake_My_Net_AA-BB-CC-DD-EE-FF_'
            '2026-01-01T00-00-00.cap')
SAE_CAP = ('sae_handshake_TestNet_AA-BB-CC-DD-EE-FF_'
           '2026-01-01T00-00-00.cap')
SAE_CAP_NO_DATE = 'sae_handshake_TestNet2_11-22-33-44-55-66.cap'
PMKID = ('pmkid_TestNet_AA-BB-CC-DD-EE-FF_'
         '2026-01-01T00-00-00.22000')
SAE_HASH = ('sae_handshake_TestNet_AA-BB-CC-DD-EE-FF_'
            '2026-01-01T00-00-00.22000')

FILES = [FOUR_WAY, SAE_CAP, SAE_CAP_NO_DATE, PMKID, SAE_HASH,
         'notes.txt', 'handshake_malformed.cap']


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
            patch('wifite.util.crack.Handshake.has_handshake',
                  return_value=True),
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
        self.assertEqual(len(CrackHelper.get_handshakes()), 5)

    def test_essid_with_underscore_is_kept(self):
        found = self._by_name(CrackHelper.get_handshakes())
        hs = found[FOUR_WAY]
        self.assertEqual(hs['essid'], 'My_Net')
        self.assertEqual(hs['bssid'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(hs['type'], '4-WAY')

    def test_sae_capture_is_discovered(self):
        found = self._by_name(CrackHelper.get_handshakes())
        hs = found[SAE_CAP]
        self.assertEqual(hs['type'], 'SAE')
        self.assertEqual(hs['essid'], 'TestNet')
        self.assertEqual(hs['date'], '2026-01-01 00:00:00')

    def test_sae_without_date_uses_mtime(self):
        found = self._by_name(CrackHelper.get_handshakes())
        hs = found[SAE_CAP_NO_DATE]
        self.assertEqual(hs['type'], 'SAE')
        self.assertTrue(hs['date'])

    def test_pmkid_is_discovered(self):
        found = self._by_name(CrackHelper.get_handshakes())
        self.assertEqual(found[PMKID]['type'], 'PMKID')

    def test_sae_hash_is_labelled_sae(self):
        found = self._by_name(CrackHelper.get_handshakes())
        self.assertEqual(found[SAE_HASH]['type'], 'SAE')

    def test_hashcat_captures_skipped_without_hashcat(self):
        with patch('wifite.util.crack.Process.exists',
                   side_effect=lambda name: name != 'hashcat'):
            found = self._by_name(CrackHelper.get_handshakes())
        self.assertNotIn(PMKID, found)
        self.assertNotIn(SAE_CAP, found)
        self.assertNotIn(SAE_HASH, found)
        self.assertIn(FOUR_WAY, found)

    def test_sae_cap_skipped_without_hcxpcapngtool(self):
        with patch('wifite.util.crack.Process.exists',
                   side_effect=lambda name: name != 'hcxpcapngtool'):
            found = self._by_name(CrackHelper.get_handshakes())
        self.assertNotIn(SAE_CAP, found)
        self.assertIn(SAE_HASH, found)

    def test_invalid_four_way_is_skipped(self):
        with patch('wifite.util.crack.Handshake.has_handshake',
                   return_value=False):
            found = self._by_name(CrackHelper.get_handshakes())
        self.assertNotIn(FOUR_WAY, found)
        self.assertIn(PMKID, found)

    def test_cracked_filenames_loaded_once(self):
        with patch.object(CrackHelper, 'cracked_filenames',
                          return_value=set()) as loader:
            CrackHelper.get_handshakes()
        loader.assert_called_once()

    def test_corrupt_cracked_file_does_not_abort_discovery(self):
        with open(self.cracked, 'w') as f:
            f.write('{not valid json')
        self.assertFalse(CrackHelper.is_cracked('anything.cap'))
        self.assertEqual(len(CrackHelper.get_handshakes()), 5)


class TestMissingToolGuard(unittest.TestCase):

    @staticmethod
    def _hs(hs_type, filename):
        return {'type': hs_type, 'filename': filename}

    def test_pmkid_needs_hashcat_binary(self):
        reason = CrackHelper._skip_reason(
            self._hs('PMKID', PMKID), {'hashcat': ['hashcat']})
        self.assertIn('hashcat', reason)

    def test_sae_hash_needs_hashcat_binary(self):
        reason = CrackHelper._skip_reason(
            self._hs('SAE', SAE_HASH), {'hashcat': ['hashcat']})
        self.assertIn('hashcat', reason)

    def test_sae_cap_needs_converter(self):
        reason = CrackHelper._skip_reason(
            self._hs('SAE', SAE_CAP), {'hashcat': ['hcxpcapngtool']})
        self.assertIn('hcxpcapngtool', reason)

    def test_pmkid_does_not_need_converter(self):
        self.assertIsNone(CrackHelper._skip_reason(
            self._hs('PMKID', PMKID), {'hashcat': ['hcxpcapngtool']}))

    def test_four_way_is_not_gated(self):
        self.assertIsNone(CrackHelper._skip_reason(
            self._hs('4-WAY', FOUR_WAY), {'hashcat': ['hashcat']}))


if __name__ == '__main__':
    unittest.main()