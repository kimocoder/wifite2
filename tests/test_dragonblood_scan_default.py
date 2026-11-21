#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Dragonblood detection mode must finish without an external interrupt."""

import unittest
from unittest.mock import patch

from wifite.config import Configuration
from wifite.util.dragonblood_scanner import DragonbloodScanner
from wifite.wifite import Wifite


class TestDragonbloodDefaultScan(unittest.TestCase):

    def setUp(self):
        self._saved_scan_time = Configuration.scan_time

    def tearDown(self):
        Configuration.scan_time = self._saved_scan_time

    def _run(self, scan_time, targets):
        Configuration.scan_time = scan_time
        app = Wifite.__new__(Wifite)

        def scan_targets(items):
            DragonbloodScanner._display_scan_results(len(items), 0, [])
            return {'vulnerable_count': 0}

        with patch('wifite.util.scanner.Scanner') as scanner_cls, \
                patch('wifite.util.dragonblood_scanner.DragonbloodScanner.scan_targets',
                      side_effect=scan_targets), \
                patch('wifite.wifite.Color.pl') as color:
            scanner_cls.return_value.get_all_targets.return_value = targets
            app.dragonblood_scan()

        return [str(call.args[0]) for call in color.call_args_list if call.args]

    def test_default_scan_time_is_finite(self):
        messages = self._run(0, [object()])
        self.assertEqual(Configuration.scan_time, 30)
        self.assertTrue(any('scanning for' in m and '30' in m for m in messages))

    def test_explicit_scan_time_is_kept(self):
        messages = self._run(10, [object()])
        self.assertEqual(Configuration.scan_time, 10)
        self.assertFalse(any('scanning for' in m for m in messages))

    def test_no_duplicate_no_vulnerability_message(self):
        messages = self._run(0, [object()])
        count = sum('No Dragonblood vulnerabilities detected' in m
                    for m in messages)
        self.assertEqual(count, 1)

    def test_no_targets_returns_after_scan(self):
        messages = self._run(0, [])
        self.assertEqual(Configuration.scan_time, 30)
        self.assertTrue(any('No targets found' in m for m in messages))


if __name__ == '__main__':
    unittest.main()