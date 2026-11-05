#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Infinite mode must survive an empty scan without hiding real errors."""

import sys
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration
from wifite.util.scanner import Scanner

pytestmark = pytest.mark.timeout(30)


class EmptyScanTest(unittest.TestCase):
    def _select(self, infinite_mode, err_msg=None):
        scanner = Scanner.__new__(Scanner)
        scanner.target = None
        scanner.targets = []
        scanner.err_msg = err_msg

        with patch.object(Configuration, 'infinite_mode', infinite_mode), \
             patch.object(Scanner, '_diagnose_no_targets'), \
             patch('wifite.util.scanner.Color.pl'):
            return scanner.select_targets()

    def test_infinite_mode_returns_empty_list(self):
        assert self._select(infinite_mode=True) == []

    def test_normal_mode_raises_on_empty_scan(self):
        with pytest.raises(Exception, match='No targets found'):
            self._select(infinite_mode=False)

    def test_scanner_error_still_raises_in_infinite_mode(self):
        with pytest.raises(Exception, match='No targets found'):
            self._select(infinite_mode=True, err_msg='airodump-ng failed')


if __name__ == '__main__':
    unittest.main()