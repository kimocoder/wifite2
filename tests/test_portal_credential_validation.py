#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for captive-portal credential input validation."""

import unittest

from wifite.attack.portal.credential_handler import CredentialHandler


class TestCredentialInputValidation(unittest.TestCase):
    def setUp(self):
        self.handler = CredentialHandler()

    def test_accepts_normal_credentials(self):
        self.assertIsNone(self.handler._validate_input('TestNetwork', 'password123'))

    def test_accepts_quotes_and_backslashes(self):
        # These are neutralized later by hex encoding / PSK derivation.
        self.assertIsNone(
            self.handler._validate_input('Evil"SSID\\1', 'Pass"word\\123'))
        self.assertIsNone(
            self.handler._validate_input('TestNetwork', 'Pass"word\\123'))

    def test_rejects_newline_in_ssid(self):
        error = self.handler._validate_input('Evil\nSSID', 'password123')
        self.assertIn('control', error)

    def test_rejects_newline_in_password(self):
        error = self.handler._validate_input('TestNetwork', 'password\n123')
        self.assertIn('control', error)

    def test_rejects_nul_and_other_controls(self):
        self.assertIn('control', self.handler._validate_input('Evil\x00SSID', 'password123'))
        self.assertIn('control', self.handler._validate_input('TestNetwork', 'pass\x1fword'))

    def test_rejects_ssid_over_32_utf8_bytes(self):
        error = self.handler._validate_input('é' * 17, 'password123')
        self.assertIn('too long', error)

    def test_rejects_empty_or_short_values(self):
        self.assertIn('empty', self.handler._validate_input('', 'password123'))
        self.assertIn('empty', self.handler._validate_input('TestNetwork', ''))
        self.assertIn('too short', self.handler._validate_input('TestNetwork', 'short'))


if __name__ == '__main__':
    unittest.main()