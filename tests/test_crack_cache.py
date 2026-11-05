#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Negative cache: skip a wordlist already exhausted for the same target."""

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.util import crack_cache

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'
ESSID = 'CYBERSPACE'


class CrackCacheTest(unittest.TestCase):
    def setUp(self):
        crack_cache.clear()

    def tearDown(self):
        crack_cache.clear()

    def test_mark_and_query(self):
        assert crack_cache.is_exhausted(BSSID, '/tmp/words.txt') is False
        crack_cache.mark_exhausted(BSSID, '/tmp/words.txt')
        assert crack_cache.is_exhausted(BSSID, '/tmp/words.txt') is True

    def test_bssid_is_case_insensitive(self):
        crack_cache.mark_exhausted(BSSID, '/tmp/words.txt')
        assert crack_cache.is_exhausted(BSSID.lower(), '/tmp/words.txt') is True

    def test_other_target_is_not_affected(self):
        crack_cache.mark_exhausted(BSSID, '/tmp/words.txt')
        assert crack_cache.is_exhausted('AA:BB:CC:DD:EE:FF', '/tmp/words.txt') is False

    def test_clear(self):
        crack_cache.mark_exhausted(BSSID, '/tmp/words.txt')
        crack_cache.clear()
        assert crack_cache.is_exhausted(BSSID, '/tmp/words.txt') is False


class PmkidSkipsExhaustedWordlistTest(unittest.TestCase):
    def setUp(self):
        crack_cache.clear()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.wordlist = os.path.join(self.tmpdir.name, 'words.txt')
        with open(self.wordlist, 'w') as handle:
            handle.write('password\n')

    def tearDown(self):
        crack_cache.clear()
        self.tmpdir.cleanup()

    def _attack(self):
        from wifite.attack.pmkid import AttackPMKID
        attack = AttackPMKID.__new__(AttackPMKID)
        attack.target = SimpleNamespace(essid=ESSID, bssid=BSSID)
        attack.view = None
        attack.crack_error = False
        return attack

    def test_exhausted_wordlist_is_skipped(self):
        crack_cache.mark_exhausted(BSSID, self.wordlist)
        attack = self._attack()

        with patch('wifite.attack.pmkid.Configuration') as config, \
             patch('wifite.attack.pmkid.Hashcat.order_wordlists',
                   side_effect=lambda lists: lists), \
             patch('wifite.attack.pmkid.HashcatCracker') as cracker_cls, \
             patch('wifite.attack.pmkid.Color.pattack'), \
             patch('wifite.attack.pmkid.Color.pl'):
            config.wordlist = self.wordlist
            config.wordlists = [self.wordlist]
            config.verbose = 0
            result = attack.crack_pmkid_file('/tmp/pmkid.22000')

        assert result is False
        cracker_cls.assert_not_called()

    def test_miss_is_recorded_when_hashcat_ran(self):
        attack = self._attack()
        cracker = MagicMock()
        cracker.device_error = False
        cracker.run_error = False
        cracker.is_finished.return_value = True
        cracker.get_result.return_value = None
        cracker_cls = MagicMock()
        cracker_cls.return_value.__enter__.return_value = cracker

        with patch('wifite.attack.pmkid.Configuration') as config, \
             patch('wifite.attack.pmkid.Hashcat.order_wordlists',
                   side_effect=lambda lists: lists), \
             patch('wifite.attack.pmkid.HashcatCracker', cracker_cls), \
             patch('wifite.attack.pmkid.Color.pattack'), \
             patch('wifite.attack.pmkid.Color.pl'):
            config.wordlist = self.wordlist
            config.wordlists = [self.wordlist]
            config.verbose = 0
            result = attack.crack_pmkid_file('/tmp/pmkid.22000')

        assert result is False
        assert crack_cache.is_exhausted(BSSID, self.wordlist) is True


class WpaSkipsExhaustedWordlistTest(unittest.TestCase):
    def setUp(self):
        crack_cache.clear()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.wordlist = os.path.join(self.tmpdir.name, 'words.txt')
        with open(self.wordlist, 'w') as handle:
            handle.write('password\n')

    def tearDown(self):
        crack_cache.clear()
        self.tmpdir.cleanup()

    def test_exhausted_wordlist_is_skipped(self):
        from wifite.attack.wpa import AttackWPA

        target = MagicMock()
        target.bssid = BSSID
        target.essid = ESSID
        target.essid_known = True
        target.channel = 6
        target.power = 50
        target.wps = 1
        target.wpa_ft = False
        target.primary_authentication = 'PSK'

        handshake = MagicMock()
        handshake.capfile = '/tmp/capture.cap'
        handshake.essid = ESSID
        handshake.bssid = BSSID

        crack_cache.mark_exhausted(BSSID, self.wordlist)
        attack = AttackWPA(target)

        with patch.object(AttackWPA, '_get_interface_assignment',
                          return_value=None), \
             patch.object(AttackWPA, 'capture_handshake',
                          return_value=handshake), \
             patch('wifite.attack.wpa.WpaSecUploader.should_upload',
                   return_value=False), \
             patch('wifite.attack.wpa.Hashcat.order_wordlists',
                   side_effect=lambda lists: lists), \
             patch('wifite.attack.wpa.HashcatCracker') as cracker_cls, \
             patch('wifite.attack.wpa.Configuration') as config:
            config.wps_only = False
            config.use_pmkid_only = False
            config.skip_crack = False
            config.wordlist = self.wordlist
            config.wordlists = [self.wordlist]
            config.verbose = 0
            result = attack.run()

        assert result is False
        cracker_cls.assert_not_called()


if __name__ == '__main__':
    unittest.main()