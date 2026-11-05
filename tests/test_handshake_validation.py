#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Handshake acceptance: crackable EAPOL pair + hcxpcapngtool cross-check."""

import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.model.handshake import Handshake
from wifite.tools.hcxdumptool import HcxPcapngTool
from wifite.tools.tshark import Tshark

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'
BSSID_HEX = '5ce28c23dcb0'
CLIENT_HEX = '112233445566'
ESSID = 'CYBERSPACE'
ESSID_HEX = '43594245525350414345'


def summary(*messages):
    return {BSSID.lower(): set(messages)}


def hash_line(kind):
    return (
        f'WPA*{kind}*0123456789abcdef0123456789abcdef*{BSSID_HEX}'
        f'*{CLIENT_HEX}*{ESSID_HEX}***'
    )


class HandshakeValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.capfile = f'{self.tmpdir.name}/capture.pcapng'
        with open(self.capfile, 'wb') as handle:
            handle.write(b'\x00')

    def tearDown(self):
        self.tmpdir.cleanup()

    def _handshake(self):
        return Handshake(self.capfile, bssid=BSSID, essid=ESSID)

    def _validate(self, messages, hcx_lines=None):
        def fake_convert(_input, output, bssid=None, essid=None):
            with open(output, 'w') as handle:
                for line in (hcx_lines or []):
                    handle.write(line + '\n')
            return bool(hcx_lines)

        with patch.object(Tshark, 'exists', return_value=True), \
             patch.object(Tshark, 'eapol_message_summary',
                          return_value=messages), \
             patch.object(HcxPcapngTool, 'exists', return_value=True), \
             patch.object(HcxPcapngTool, 'convert_to_hashcat',
                          side_effect=fake_convert):
            return self._handshake().has_handshake()

    def test_single_message_is_rejected(self):
        assert self._validate(summary(1)) is False

    def test_m1_m2_is_accepted(self):
        assert self._validate(summary(1, 2), [hash_line('02')]) is True

    def test_m2_m3_is_accepted(self):
        assert self._validate(summary(2, 3), [hash_line('02')]) is True

    def test_m1_m3_is_rejected(self):
        assert self._validate(summary(1, 3)) is False

    def test_no_eapol_frames_is_rejected(self):
        assert self._validate({}) is False

    def test_pmkid_only_hash_is_not_a_handshake(self):
        assert self._validate(summary(1, 2), [hash_line('01')]) is False

    def test_target_eapol_hash_is_accepted(self):
        assert self._validate(summary(1, 2), [hash_line('02')]) is True

    def test_hash_for_other_bssid_is_rejected(self):
        other = hash_line('02').replace(BSSID_HEX, 'aabbccddeeff')
        assert self._validate(summary(1, 2), [other]) is False

    def test_no_validator_available_is_rejected(self):
        with patch.object(Tshark, 'exists', return_value=False), \
             patch.object(HcxPcapngTool, 'exists', return_value=False):
            assert self._handshake().has_handshake() is False


if __name__ == '__main__':
    unittest.main()