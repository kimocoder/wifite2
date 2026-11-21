#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Non-interactive --crack selection via --crack-all/--crack-index/--crack-tool."""

import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

from wifite.config import Configuration
from wifite.util.crack import CrackHelper

pytestmark = pytest.mark.timeout(30)

A = {'filename': '/hs/a.cap', 'bssid': 'AA:BB:CC:DD:EE:01',
     'essid': 'A', 'date': '2026-01-01 00:00:00', 'type': '4-WAY'}
B = {'filename': '/hs/b.cap', 'bssid': 'AA:BB:CC:DD:EE:02',
     'essid': 'B', 'date': '2026-01-01 00:00:00', 'type': '4-WAY'}


class TestNonInteractiveCrack(unittest.TestCase):

    def setUp(self):
        handle, self.wordlist = tempfile.mkstemp(suffix='.txt')
        os.close(handle)
        self._saved = {
            name: getattr(Configuration, name)
            for name in ('wordlist', 'wordlists', 'crack_all',
                         'crack_index', 'crack_tool', 'verbose',
                         'show_cracking_command')
        }
        Configuration.wordlist = self.wordlist
        Configuration.wordlists = [self.wordlist]
        Configuration.crack_all = False
        Configuration.crack_index = None
        Configuration.crack_tool = 'aircrack'
        Configuration.verbose = 0
        Configuration.show_cracking_command = False

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(Configuration, name, value)
        os.remove(self.wordlist)

    def _run(self, handshakes, missing=()):
        def exists(name):
            return name not in missing

        with patch.object(Configuration, 'initialize'), \
                patch.object(CrackHelper, 'get_handshakes',
                             return_value=handshakes), \
                patch.object(CrackHelper, 'crack') as crack, \
                patch('wifite.util.crack.Process.exists',
                      side_effect=exists), \
                patch('wifite.util.crack.John.is_wpapsk_capable',
                      return_value=True), \
                patch('wifite.util.crack.Color'):
            CrackHelper.run()
        return [call.args[0]['essid'] for call in crack.call_args_list]

    def test_crack_all_cracks_everything(self):
        Configuration.crack_all = True
        self.assertEqual(self._run([A, B]), ['A', 'B'])

    def test_crack_index_selects_one(self):
        Configuration.crack_index = '2'
        self.assertEqual(self._run([A, B]), ['B'])

    def test_crack_index_range(self):
        Configuration.crack_index = '1-2'
        self.assertEqual(self._run([A, B]), ['A', 'B'])

    def test_invalid_crack_index_cracks_nothing(self):
        Configuration.crack_index = '9'
        self.assertEqual(self._run([A, B]), [])

    def test_unavailable_tool_cracks_nothing(self):
        Configuration.crack_all = True
        Configuration.crack_tool = 'cowpatty'
        self.assertEqual(self._run([A, B], missing=('cowpatty',)), [])


class TestSaeHashAndPmkid(unittest.TestCase):

    def setUp(self):
        self._saved = {
            name: getattr(Configuration, name)
            for name in ('wordlists', 'show_cracking_command', 'verbose')
        }
        Configuration.wordlists = ['/tmp/wordlist.txt']
        Configuration.show_cracking_command = False
        Configuration.verbose = 0

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(Configuration, name, value)

    def test_sae_22000_uses_hash_cracker_with_sae_result(self):
        from wifite.model.sae_result import CrackResultSAE

        hs = {'type': 'SAE', 'filename': '/hs/sae.22000',
              'bssid': 'AA:BB:CC:DD:EE:FF', 'essid': 'SAE'}
        with patch.object(CrackHelper, 'crack_pmkid',
                          return_value=None) as pmkid, \
                patch.object(CrackHelper, 'crack_sae') as sae_cap, \
                patch('wifite.util.crack.Color'):
            CrackHelper.crack(hs, 'hashcat')

        pmkid.assert_called_once()
        self.assertIs(pmkid.call_args.kwargs['result_cls'], CrackResultSAE)
        sae_cap.assert_not_called()

    def test_crack_pmkid_still_runs_hashcat_for_other_tool(self):
        hs = {'type': 'PMKID', 'filename': '/hs/p.22000',
              'bssid': 'AA:BB:CC:DD:EE:FF', 'essid': 'PMKID'}
        with patch('wifite.util.crack.Hashcat.crack_pmkid',
                   return_value='secret') as crack, \
                patch('wifite.util.crack.Color'):
            result = CrackHelper.crack_pmkid(hs, 'aircrack')

        crack.assert_called_once()
        self.assertEqual(result.key, 'secret')


if __name__ == '__main__':
    unittest.main()