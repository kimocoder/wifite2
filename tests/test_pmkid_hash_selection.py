#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""get_pmkid_hash must prefer PMKID records over EAPOL records."""

import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration
from wifite.tools.hashcat import HcxPcapngTool

pytestmark = pytest.mark.timeout(30)

BSSID = 'AA:BB:CC:DD:EE:FF'
OTHER_BSSID = '001122334455'
ESSID_HEX = '546573744e6574776f726b'


def pmkid_line(kind='01', bssid='aabbccddeeff'):
    return (f'WPA*{kind}*0123456789abcdef0123456789abcdef*{bssid}'
            f'*112233445566*{ESSID_HEX}***')


def eapol_line(kind='02', bssid='aabbccddeeff'):
    return (f'WPA*{kind}*0123456789abcdef0123456789abcdef*{bssid}'
            f'*112233445566*{ESSID_HEX}*11223344556677889900aabbccddeeff'
            f'*{"ab" * 221}*02')


class TestPmkidHashSelection(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _get_hash(self, payload):
        target = SimpleNamespace(bssid=BSSID)
        with patch.object(
                Configuration, 'temp',
                side_effect=lambda sub='': os.path.join(self.tmpdir, sub)):
            tool = HcxPcapngTool(target)

        def fake_process(command, *args, **kwargs):
            out_path = command[command.index('-o') + 1]
            with open(out_path, 'w') as fh:
                fh.write(payload)
            return MagicMock()

        with patch('wifite.tools.hashcat.Process', side_effect=fake_process):
            return tool.get_pmkid_hash('/tmp/capture.pcapng')

    def test_prefers_pmkid_even_when_eapol_comes_first(self):
        payload = eapol_line() + '\n' + pmkid_line() + '\n'
        self.assertEqual(self._get_hash(payload), pmkid_line())

    def test_prefers_ft_pmkid_over_ft_eapol(self):
        payload = eapol_line('04') + '\n' + pmkid_line('03') + '\n'
        self.assertEqual(self._get_hash(payload), pmkid_line('03'))

    def test_falls_back_to_eapol_when_no_pmkid(self):
        payload = eapol_line() + '\n'
        self.assertEqual(self._get_hash(payload), eapol_line())

    def test_ignores_records_for_other_bssids(self):
        payload = (eapol_line(bssid=OTHER_BSSID) + '\n' +
                   pmkid_line(bssid=OTHER_BSSID) + '\n' +
                   pmkid_line() + '\n')
        self.assertEqual(self._get_hash(payload), pmkid_line())

    def test_skips_malformed_lines(self):
        payload = 'garbage\nWPA*01*short\n' + pmkid_line() + '\n'
        self.assertEqual(self._get_hash(payload), pmkid_line())

    def test_returns_none_without_a_match(self):
        payload = pmkid_line(bssid=OTHER_BSSID) + '\n'
        self.assertIsNone(self._get_hash(payload))


if __name__ == '__main__':
    unittest.main()