#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Hashcat 8 (WPA-FT-PSK) compatibility gating tests."""

import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.tools.hashcat import Hashcat

pytestmark = pytest.mark.timeout(30)

ESSID_HEX = '546573744e6574776f726b'
MAC_AP = 'aabbccddeeff'
MAC_CLIENT = '112233445566'


def pmkid_line(kind='01'):
    return f'WPA*{kind}*0123456789abcdef0123456789abcdef*{MAC_AP}*{MAC_CLIENT}*{ESSID_HEX}***'


def eapol_line(kind='02', eapol_bytes=221):
    eapol = 'ab' * eapol_bytes
    return (
        f'WPA*{kind}*0123456789abcdef0123456789abcdef*{MAC_AP}*{MAC_CLIENT}'
        f'*{ESSID_HEX}*11223344556677889900aabbccddeeff*{eapol}*02'
    )


class TestInspectHashFile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _inspect(self, content):
        path = os.path.join(self.tmpdir, 'hashes.22000')
        with open(path, 'w') as fh:
            fh.write(content)
        return Hashcat.inspect_hash_file(path)

    def test_plain_pmkid_needs_no_hashcat8(self):
        info = self._inspect(pmkid_line('01') + '\n')
        self.assertFalse(info['needs_hashcat8'])
        self.assertEqual(info['types'], {'01'})

    def test_ft_pmkid_requires_hashcat8(self):
        info = self._inspect(pmkid_line('03') + '\n')
        self.assertTrue(info['needs_hashcat8'])

    def test_ft_eapol_requires_hashcat8(self):
        info = self._inspect(eapol_line('04') + '\n')
        self.assertTrue(info['needs_hashcat8'])

    def test_large_eapol_requires_hashcat8(self):
        info = self._inspect(eapol_line('02', eapol_bytes=300) + '\n')
        self.assertTrue(info['needs_hashcat8'])
        self.assertEqual(info['max_eapol_bytes'], 300)

    def test_standard_eapol_is_fine(self):
        info = self._inspect(eapol_line('02', eapol_bytes=221) + '\n')
        self.assertFalse(info['needs_hashcat8'])

    def test_empty_or_missing_file(self):
        self.assertFalse(self._inspect('')['needs_hashcat8'])
        missing = Hashcat.inspect_hash_file(os.path.join(self.tmpdir, 'nope.22000'))
        self.assertFalse(missing['needs_hashcat8'])


class TestHashcat8Support(unittest.TestCase):
    def setUp(self):
        self._original = Hashcat._cached_version
        Hashcat._cached_version = None

    def tearDown(self):
        Hashcat._cached_version = self._original

    def test_hashcat_7_does_not_support_ft(self):
        Hashcat._cached_version = (7, 1, 2)
        self.assertFalse(Hashcat.supports_ft_hashes())

    def test_hashcat_8_supports_ft(self):
        Hashcat._cached_version = (8, 0, 0)
        self.assertTrue(Hashcat.supports_ft_hashes())

    def test_compat_check_true_when_not_needed(self):
        Hashcat._cached_version = (7, 1, 2)
        with patch.object(Hashcat, 'inspect_hash_file',
                          return_value={'types': {'01'}, 'needs_hashcat8': False,
                                        'max_eapol_bytes': 0}):
            self.assertTrue(Hashcat.check_hash_file_compat('unused'))

    def test_compat_check_false_on_old_hashcat(self):
        Hashcat._cached_version = (7, 1, 2)
        with patch.object(Hashcat, 'inspect_hash_file',
                          return_value={'types': {'03'}, 'needs_hashcat8': True,
                                        'max_eapol_bytes': 0}), \
             patch('wifite.tools.hashcat.Color.pl') as mock_pl:
            self.assertFalse(Hashcat.check_hash_file_compat('unused'))
            self.assertTrue(mock_pl.called)


if __name__ == '__main__':
    unittest.main()