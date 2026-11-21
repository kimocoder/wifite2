#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Native wpa-sec upload must not expose the API key in argv."""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import requests

from wifite.config import Configuration
from wifite.config.parsers.wpasec import parse_wpasec_args
from wifite.tools.wlancap2wpasec import Wlancap2wpasec

pytestmark = pytest.mark.timeout(30)

KEY = 'a' * 32


class TestNativeUpload(unittest.TestCase):

    def setUp(self):
        fd, self.capfile = tempfile.mkstemp(suffix='.cap')
        os.write(fd, b'\xd4\xc3\xb2\xa1 test capture')
        os.close(fd)

    def tearDown(self):
        if os.path.exists(self.capfile):
            os.remove(self.capfile)

    def test_key_travels_in_cookie_not_argv(self):
        response = Mock(status_code=200, text='upload ok', reason='OK')
        with patch('requests.post', return_value=response) as post, \
                patch('wifite.tools.wlancap2wpasec.Process') as process:
            ok, message = Wlancap2wpasec.upload(self.capfile, KEY, timeout=5)

        self.assertTrue(ok, message)
        process.assert_not_called()
        url = post.call_args.args[0]
        kwargs = post.call_args.kwargs
        self.assertNotIn(KEY, url)
        self.assertEqual(kwargs['headers']['Cookie'], f'key={KEY}')
        self.assertIn('file', kwargs['files'])
        self.assertEqual(kwargs['timeout'], 5)

    def test_remove_on_success(self):
        response = Mock(status_code=200, text='upload ok', reason='OK')
        with patch('requests.post', return_value=response):
            ok, message = Wlancap2wpasec.upload(
                self.capfile, KEY, remove_on_success=True)

        self.assertTrue(ok, message)
        self.assertFalse(os.path.exists(self.capfile))

    def test_auth_failure_is_reported(self):
        response = Mock(status_code=401, text='unauthorized', reason='Unauthorized')
        with patch('requests.post', return_value=response):
            ok, message = Wlancap2wpasec.upload(self.capfile, KEY)

        self.assertFalse(ok)
        self.assertIn('Authentication failed', message)

    def test_empty_response_is_not_confirmed(self):
        response = Mock(status_code=200, text='', reason='OK')
        with patch('requests.post', return_value=response):
            ok, message = Wlancap2wpasec.upload(self.capfile, KEY)

        self.assertFalse(ok)
        self.assertIn('not confirmed', message)

    def test_timeout_is_reported(self):
        with patch('requests.post', side_effect=requests.exceptions.Timeout):
            ok, message = Wlancap2wpasec.upload(self.capfile, KEY, timeout=5)

        self.assertFalse(ok)
        self.assertIn('timed out', message)


class TestEnvApiKey(unittest.TestCase):

    def setUp(self):
        self._saved = (Configuration.wpasec_enabled,
                       Configuration.wpasec_api_key)
        Configuration.wpasec_enabled = False
        Configuration.wpasec_api_key = None

    def tearDown(self):
        (Configuration.wpasec_enabled,
         Configuration.wpasec_api_key) = self._saved

    def test_env_key_used_when_wpasec_requested(self):
        args = SimpleNamespace(wpasec_enabled=True, wpasec_api_key=None)
        with patch.dict(os.environ, {'WIFITE_WPASEC_KEY': KEY}), \
                patch('wifite.config.parsers.wpasec.Color.pl'):
            parse_wpasec_args(Configuration, args)

        self.assertEqual(Configuration.wpasec_api_key, KEY)
        self.assertTrue(Configuration.wpasec_enabled)

    def test_env_key_ignored_without_wpasec(self):
        args = SimpleNamespace(wpasec_enabled=False, wpasec_api_key=None)
        with patch.dict(os.environ, {'WIFITE_WPASEC_KEY': KEY}), \
                patch('wifite.config.parsers.wpasec.Color.pl'):
            parse_wpasec_args(Configuration, args)

        self.assertIsNone(Configuration.wpasec_api_key)
        self.assertFalse(Configuration.wpasec_enabled)

    def test_key_file_alone_does_not_enable_uploads(self):
        args = SimpleNamespace(wpasec_enabled=False, wpasec_api_key=KEY)
        with patch('wifite.config.parsers.wpasec.Color.pl'):
            parse_wpasec_args(Configuration, args)

        self.assertEqual(Configuration.wpasec_api_key, KEY)
        self.assertFalse(Configuration.wpasec_enabled)

    def test_key_file_value_wins_over_environment(self):
        file_key = 'b' * 32
        args = SimpleNamespace(wpasec_enabled=True, wpasec_api_key=file_key)
        with patch.dict(os.environ, {'WIFITE_WPASEC_KEY': KEY}), \
                patch('wifite.config.parsers.wpasec.Color.pl'):
            parse_wpasec_args(Configuration, args)

        self.assertEqual(Configuration.wpasec_api_key, file_key)


if __name__ == '__main__':
    unittest.main()