#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for WPS-specific command-line configuration."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wifite.config.parsers.wps import parse_wps_args


class TestWPSConfigParser(unittest.TestCase):
    """Verify that independent WPS exclusions can be combined."""

    @staticmethod
    def _parse(**overrides):
        class Config:
            no_wps = False
            wps_filter = False
            wps_only = False
            wps_pixie = True
            wps_no_nullpin = True
            wps_pin = True

        values = {
            'wps_filter': False,
            'wps_only': False,
            'no_wps': False,
            'wps_pixie': False,
            'wps_no_pixie': False,
            'wps_no_nullpin': False,
            'use_bully': False,
            'use_reaver': False,
            'wps_pixie_timeout': None,
            'wps_fail_threshold': None,
            'wps_timeout_threshold': None,
            'wps_ignore_lock': False,
        }
        values.update(overrides)

        with patch('wifite.config.parsers.wps.Color.pl'):
            parse_wps_args(Config, SimpleNamespace(**values))
        return Config

    @staticmethod
    def _enabled_attacks(config):
        """Return effective Pixie, NULL PIN and regular PIN availability."""
        return (
            config.wps_pixie,
            config.wps_pin and config.wps_no_nullpin,
            config.wps_pin,
        )

    def test_wps_mode_flag_intersection_matrix(self):
        # --pixie takes precedence over the contradictory --no-pixie flag,
        # matching the parser's existing mode-selection behavior.
        matrix = (
            # --pixie, --no-pixie, --no-nullpin, raw config, enabled attacks
            (False, False, False, (True, True, True), (True, True, True)),
            (False, False, True,  (True, False, True), (True, False, True)),
            (False, True,  False, (False, True, True), (False, True, True)),
            (False, True,  True,  (False, False, True), (False, False, True)),
            (True,  False, False, (True, True, False), (True, False, False)),
            (True,  False, True,  (True, False, False), (True, False, False)),
            (True,  True,  False, (True, True, False), (True, False, False)),
            (True,  True,  True,  (True, False, False), (True, False, False)),
        )

        for pixie, no_pixie, no_nullpin, expected_config, expected_attacks in matrix:
            with self.subTest(pixie=pixie, no_pixie=no_pixie, no_nullpin=no_nullpin):
                config = self._parse(
                    wps_pixie=pixie,
                    wps_no_pixie=no_pixie,
                    wps_no_nullpin=no_nullpin,
                )
                raw_config = (
                    config.wps_pixie,
                    config.wps_no_nullpin,
                    config.wps_pin,
                )

                self.assertEqual(raw_config, expected_config)
                self.assertEqual(self._enabled_attacks(config), expected_attacks)


if __name__ == '__main__':
    unittest.main()
