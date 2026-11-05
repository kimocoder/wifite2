#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Run-scoped capture cache shared between attacks."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration
from wifite.util import capture_cache

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'


class CaptureCacheTest(unittest.TestCase):
    def setUp(self):
        capture_cache.clear()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.source = os.path.join(self.tmpdir.name, 'pmkid.pcapng')
        with open(self.source, 'wb') as handle:
            handle.write(b'pcapng-data')
        self.stored = os.path.join(self.tmpdir.name, 'shared.pcapng')

    def tearDown(self):
        capture_cache.clear()
        self.tmpdir.cleanup()

    def _register(self):
        with patch.object(Configuration, 'temp', return_value=self.stored):
            return capture_cache.register(BSSID, self.source)

    def test_register_and_get(self):
        path = self._register()
        assert path == self.stored
        assert capture_cache.get(BSSID) == self.stored
        assert os.path.exists(self.stored)

    def test_get_is_case_insensitive(self):
        self._register()
        assert capture_cache.get(BSSID.lower()) == self.stored

    def test_missing_capture_is_not_published(self):
        with patch.object(Configuration, 'temp', return_value=self.stored):
            assert capture_cache.register(
                BSSID, os.path.join(self.tmpdir.name, 'nope.pcapng')) is None
        assert capture_cache.get(BSSID) is None

    def test_empty_capture_is_not_published(self):
        empty = os.path.join(self.tmpdir.name, 'empty.pcapng')
        open(empty, 'wb').close()
        with patch.object(Configuration, 'temp', return_value=self.stored):
            assert capture_cache.register(BSSID, empty) is None
        assert capture_cache.get(BSSID) is None

    def test_clear_removes_published_file(self):
        self._register()
        capture_cache.clear()
        assert capture_cache.get(BSSID) is None
        assert not os.path.exists(self.stored)

    def test_get_after_file_disappears(self):
        self._register()
        os.remove(self.stored)
        assert capture_cache.get(BSSID) is None


if __name__ == '__main__':
    unittest.main()