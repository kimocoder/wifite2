#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Configurable WEP fake-authentication timeout."""

import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.attack.wep import AttackWEP
from wifite.config import Configuration
from wifite.config.defaults import initialize_defaults

pytestmark = pytest.mark.timeout(30)


class WepFakeauthTimeTest(unittest.TestCase):
    def _fake_auth(self, configured):
        attack = AttackWEP.__new__(AttackWEP)
        attack.target = SimpleNamespace(bssid='AA:BB:CC:DD:EE:FF')

        with patch.object(Configuration, 'wep_fakeauth_time', configured), \
             patch.object(Configuration, 'require_fakeauth', False), \
             patch('wifite.attack.wep.Aireplay.fakeauth',
                   return_value=True) as fakeauth, \
             patch('wifite.attack.wep.Color.p'), \
             patch('wifite.attack.wep.Color.pl'):
            attack.fake_auth()

        return fakeauth.call_args.kwargs['timeout']

    def test_configured_timeout_is_used(self):
        assert self._fake_auth(12) == 12

    def test_zero_falls_back_to_default(self):
        assert self._fake_auth(0) == AttackWEP.fakeauth_wait


class DefaultsTest(unittest.TestCase):
    def test_defaults_keep_dual_interface_preference(self):
        class Dummy:
            pass

        initialize_defaults(Dummy)

        assert Dummy.prefer_dual_interface is True
        assert Dummy.wep_fakeauth_time == 5
        assert Dummy.show_cracking_command is False


if __name__ == '__main__':
    unittest.main()
