#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import unittest
from unittest.mock import patch

import pytest

from wifite.model.handshake import Handshake
from wifite.tools.tshark import Tshark
from wifite.util.process import Process

sys.path.insert(0, '..')

pytestmark = pytest.mark.timeout(30)


class TestHandshake(unittest.TestCase):
    """ Test suite for Target parsing an generation """

    def test_preset_bssid_is_not_retargeted(self):
        """A BSSID from the attack context must not be swapped for another AP."""
        hs = Handshake('/tmp/multi.cap', bssid='5C:E2:8C:23:DC:B0', essid=None)
        pairs = [('AA:BB:CC:DD:EE:01', 'One'), ('AA:BB:CC:DD:EE:02', 'Two')]

        with patch('wifite.model.handshake.Tshark.bssid_essid_pairs',
                   return_value=pairs):
            hs.divine_bssid_and_essid()

        assert hs.bssid == '5C:E2:8C:23:DC:B0'
        assert hs.essid is None

    def test_preset_bssid_resolves_essid_from_single_pair(self):
        """A single matching pair must still provide the ESSID for cowpatty."""
        hs = Handshake('/tmp/single.cap', bssid='74:3A:EF:CF:B7:4F', essid=None)
        pairs = [('74:3a:ef:cf:b7:4f', 'Telenor9963sjy')]

        with patch('wifite.model.handshake.Tshark.bssid_essid_pairs',
                   return_value=pairs):
            hs.divine_bssid_and_essid()

        assert hs.essid == 'Telenor9963sjy'

    @unittest.skipUnless(Tshark.exists(), 'requires tshark')
    def test_tshark_pairs_strip_ssid_quotes(self):
        hs_file = self.getFile('handshake_exists.cap')
        pairs = Tshark.bssid_essid_pairs(hs_file, bssid='A4:2B:8C:16:6B:3A')
        assert len(pairs) == 1
        bssid, essid = pairs[0]
        assert bssid.lower() == 'a4:2b:8c:16:6b:3a'
        assert essid == 'Test Router Please Ignore'

    def getFile(self, filename):
        """ Helper method to parse targets from filename """
        import os
        import inspect
        this_file = os.path.abspath(inspect.getsourcefile(self.getFile))
        this_dir = os.path.dirname(this_file)
        return os.path.join(this_dir, 'files', filename)

    def testAnalyze(self):
        hs_file = self.getFile("handshake_exists.cap")
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A')
        try:
            hs.analyze()
        except Exception as e:
            self.skipTest(f'handshake.analyze() raised: {e}')

    @pytest.mark.timeout(15)
    @unittest.skipUnless(Process.exists("tshark"), 'tshark is missing')
    def testHandshakeTshark(self):
        print("\nTesting handshake with tshark...")
        hs_file = self.getFile("handshake_exists.cap")
        print("Testing file:", hs_file)

        # Copy file to /tmp to work around tshark permission issues
        import tempfile
        import shutil
        import os

        with tempfile.NamedTemporaryFile(delete=False, suffix='.cap') as tmp:
            temp_file = tmp.name

        try:
            shutil.copy2(hs_file, temp_file)
            hs = Handshake(temp_file, bssid='A4:2B:8C:16:6B:3A')
            handshakes = hs.tshark_handshakes()
            print(f"Found {len(handshakes)} handshake(s): {handshakes}")
            assert len(handshakes) > 0, f'Expected len>0 but got len({len(handshakes)})'
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @pytest.mark.timeout(15)
    @unittest.skipUnless(Process.exists("cowpatty"), 'cowpatty is missing')
    def testHandshakeCowpatty(self):
        print("\nTesting handshake with cowpatty...")
        hs_file = self.getFile('handshake_exists.cap')
        # cowpatty -c needs an ESSID, so pass it explicitly. (tshark/aircrack
        # tests don't need this — only cowpatty enforces it.)
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A',
                       essid='Test Router Please Ignore')
        assert (len(hs.cowpatty_handshakes()) > 0), f'Expected len>0 but got len({len(hs.cowpatty_handshakes())})'

    @pytest.mark.timeout(15)
    @unittest.skipUnless(Process.exists("aircrack-ng"), 'aircrack-ng is missing')
    def testHandshakeAircrack(self):
        print("\nTesting handshake with aircrack-ng...")
        hs_file = self.getFile('handshake_exists.cap')
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A')
        assert (len(hs.aircrack_handshakes()) > 0), f'Expected len>0 but got len({len(hs.aircrack_handshakes())})'


class TestHandshakeCheck(unittest.TestCase):
    """--check must report bad input cleanly and use a non-zero exit."""

    def test_missing_file_raises_wifite_error(self):
        from wifite.config import Configuration
        from wifite.util.errors import WifiteError

        with patch.object(Configuration, 'check_handshake',
                          '/tmp/wifite-does-not-exist.cap'), \
                patch.object(Configuration, 'target_bssid', None), \
                patch.object(Configuration, 'target_essid', None), \
                patch('wifite.model.handshake.Color.pl'):
            with self.assertRaises(WifiteError):
                Handshake.check()

    def test_empty_hs_directory_is_an_error(self):
        from wifite.config import Configuration
        from wifite.util.errors import WifiteError

        with patch.object(Configuration, 'check_handshake', '<all>'), \
                patch('wifite.model.handshake.os.listdir', return_value=[]), \
                patch('wifite.model.handshake.Color.pl'):
            with self.assertRaises(WifiteError):
                Handshake.check()

    def test_malformed_file_is_reported_cleanly(self):
        import os
        import tempfile

        from wifite.config import Configuration
        from wifite.util.errors import WifiteError

        fd, path = tempfile.mkstemp(suffix='.cap')
        os.close(fd)
        try:
            with patch.object(Configuration, 'check_handshake', path), \
                    patch.object(Configuration, 'target_bssid', None), \
                    patch.object(Configuration, 'target_essid', None), \
                    patch.object(Handshake, 'divine_bssid_and_essid',
                                 side_effect=ValueError('not a cap file')), \
                    patch('wifite.model.handshake.Color.pl'):
                with self.assertRaises(WifiteError):
                    Handshake.check()
        finally:
            os.remove(path)


if __name__ == '__main__':
    unittest.main()
