#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""PMKID grace window: one session can yield both PMKID and handshake."""

import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.attack.pmkid import AttackPMKID

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'
ESSID = 'CYBERSPACE'
HASH = 'WPA*01*0123456789abcdef0123456789abcdef*5ce28c23dcb0*112233445566*43594245525350414345***'


class SharedHandshakeCheckTest(unittest.TestCase):
    def _attack(self):
        attack = AttackPMKID.__new__(AttackPMKID)
        attack.target = SimpleNamespace(
            bssid=BSSID, essid=ESSID, essid_known=True)
        attack.pcapng_file = '/tmp/pmkid.pcapng'
        return attack

    def test_true_when_capture_has_handshake(self):
        with patch('wifite.model.handshake.Handshake.has_handshake',
                   return_value=True):
            assert self._attack()._shared_handshake_ready() is True

    def test_false_when_capture_has_no_handshake(self):
        with patch('wifite.model.handshake.Handshake.has_handshake',
                   return_value=False):
            assert self._attack()._shared_handshake_ready() is False

    def test_false_when_capture_cannot_be_parsed(self):
        with patch('wifite.model.handshake.Handshake.has_handshake',
                   side_effect=ValueError('bad capture')):
            assert self._attack()._shared_handshake_ready() is False


class GraceWindowTest(unittest.TestCase):
    def _attack(self, grace_seconds):
        attack = AttackPMKID.__new__(AttackPMKID)
        attack.target = SimpleNamespace(
            bssid=BSSID, essid=ESSID, essid_known=True, channel=6)
        attack.view = None
        attack.pcapng_file = '/tmp/pmkid-grace-test.pcapng'
        attack.keep_capturing = None
        attack._dumptool_died = False
        attack.crack_result = None
        attack.success = False
        attack.HANDSHAKE_GRACE_SECONDS = grace_seconds
        return attack

    def _run(self, attack, handshake_ready):
        pcaptool = MagicMock()
        pcaptool.return_value.get_pmkid_hash.return_value = HASH

        with patch('wifite.attack.pmkid.Thread') as thread_cls, \
             patch('wifite.attack.pmkid.HcxPcapngTool', pcaptool), \
             patch('wifite.attack.pmkid.Timer') as timer_cls, \
             patch('wifite.attack.pmkid.Configuration') as config, \
             patch('wifite.attack.pmkid.os.path.getsize', return_value=100), \
             patch('wifite.util.process.Process.check_fd_limit',
                   return_value=False), \
             patch('wifite.attack.pmkid.active_count', return_value=0), \
             patch.object(AttackPMKID, 'save_pmkid',
                          return_value='/tmp/saved.22000') as save, \
             patch.object(AttackPMKID, '_shared_handshake_ready',
                          return_value=handshake_ready) as ready, \
             patch('wifite.attack.pmkid.Color.pattack'), \
             patch('wifite.attack.pmkid.Color.clear_entire_line'), \
             patch('wifite.attack.pmkid.Color.pl'):
            timer = MagicMock()
            timer.remaining.return_value = 30
            timer_cls.return_value = timer
            config.pmkid_timeout = 60
            config.verbose = 0
            result = attack.capture_pmkid()

        thread_cls.return_value.start.assert_called_once_with()
        return result, save, ready

    def test_handshake_in_same_session_stops_immediately(self):
        attack = self._attack(grace_seconds=10)
        result, save, ready = self._run(attack, handshake_ready=True)

        assert result == '/tmp/saved.22000'
        assert ready.call_count == 1

    def test_zero_grace_stops_after_pmkid(self):
        attack = self._attack(grace_seconds=0)
        result, save, ready = self._run(attack, handshake_ready=False)

        assert result == '/tmp/saved.22000'
        assert ready.call_count == 1


if __name__ == '__main__':
    unittest.main()