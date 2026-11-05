#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""hcxdumptool/hcxtools 8.x compatibility tests."""

import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration
from wifite.tools.hcxdumptool import (
    HcxDumpTool,
    HcxDumpToolPassive,
    HcxPcapngTool,
)
from wifite.util.hcxtools import channel_spec, filter_hash_lines

pytestmark = pytest.mark.timeout(30)

BSSID = 'AA:BB:CC:DD:EE:FF'
ESSID = 'TestNetwork'
ESSID_HEX = '546573744e6574776f726b'


def hash_line(bssid='aabbccddeeff', essid_hex=ESSID_HEX, kind='01'):
    return (
        f'WPA*{kind}*0123456789abcdef0123456789abcdef*{bssid}'
        f'*112233445566*{essid_hex}***'
    )


class TestChannelSpec(unittest.TestCase):
    def test_24ghz_gets_a_suffix(self):
        self.assertEqual(channel_spec(6), '6a')
        self.assertEqual(channel_spec(14), '14a')

    def test_5ghz_gets_b_suffix(self):
        self.assertEqual(channel_spec(36), '36b')
        self.assertEqual(channel_spec(177), '177b')

    def test_6ghz_gets_c_suffix(self):
        self.assertEqual(channel_spec(200), '200c')

    def test_explicit_band_is_preserved(self):
        self.assertEqual(channel_spec('5c'), '5c')
        self.assertEqual(channel_spec('36b'), '36b')

    def test_band_argument_selects_suffix(self):
        self.assertEqual(channel_spec(5, band='6'), '5c')
        self.assertEqual(channel_spec(37, band='6'), '37c')
        self.assertEqual(channel_spec(36, band='5'), '36b')
        self.assertEqual(channel_spec(6, band='2.4'), '6a')

    def test_none_passthrough(self):
        self.assertIsNone(channel_spec(None))

    def test_unknown_channel_has_no_band_suffix(self):
        # Airodump reports -1 when the channel could not be parsed.
        self.assertEqual(channel_spec(-1), '-1')
        self.assertEqual(channel_spec(0), '0')


class TestFilterHashLines(unittest.TestCase):
    def test_keeps_only_matching_bssid(self):
        lines = [hash_line(), hash_line(bssid='001122334455')]
        self.assertEqual(filter_hash_lines(lines, bssid=BSSID), [lines[0]])

    def test_keeps_only_matching_essid(self):
        lines = [hash_line(), hash_line(essid_hex='4f74686572')]
        self.assertEqual(filter_hash_lines(lines, essid=ESSID), [lines[0]])

    def test_both_filters_combine(self):
        lines = [
            hash_line(),
            hash_line(bssid='001122334455'),
            hash_line(essid_hex='4f74686572'),
        ]
        self.assertEqual(filter_hash_lines(lines, bssid=BSSID, essid=ESSID), [lines[0]])

    def test_no_filters_keeps_every_wpa_line(self):
        lines = [hash_line(), hash_line(bssid='001122334455')]
        self.assertEqual(filter_hash_lines(lines), lines)

    def test_malformed_lines_are_dropped(self):
        self.assertEqual(filter_hash_lines(['', 'not a hash', 'WPA*01*bad']), [])


class TestConvertToHashcat(unittest.TestCase):
    """hcxpcapngtool 8 has no --bssid/--essid, so filtering happens here."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_conversion(self, payload, return_code=0):
        out_file = os.path.join(self.tmpdir, 'out.22000')
        recorded = {}

        def fake_process(command, devnull=False):
            recorded['command'] = command
            instance = MagicMock()

            def wait():
                if return_code == 0 and payload is not None:
                    target = command[command.index('-o') + 1]
                    with open(target, 'w') as fh:
                        fh.write(payload)
                return return_code

            instance.wait.side_effect = wait
            return instance

        with patch('wifite.tools.hcxdumptool.Process', side_effect=fake_process):
            result = HcxPcapngTool.convert_to_hashcat(
                os.path.join(self.tmpdir, 'capture.pcapng'),
                out_file,
                bssid=BSSID,
                essid=ESSID,
            )
        return result, out_file, recorded['command']

    def test_does_not_pass_unsupported_filters(self):
        _, _, command = self._run_conversion(hash_line() + '\n')
        self.assertNotIn('--bssid', command)
        self.assertNotIn('--essid', command)

    def test_filters_generated_hashes(self):
        payload = '\n'.join([
            hash_line(),
            hash_line(bssid='001122334455'),
            hash_line(essid_hex='4f74686572'),
        ]) + '\n'
        result, out_file, _ = self._run_conversion(payload)

        self.assertTrue(result)
        with open(out_file) as fh:
            lines = [line for line in fh.read().splitlines() if line]
        self.assertEqual(lines, [hash_line()])

    def test_nonzero_exit_is_failure(self):
        result, _, _ = self._run_conversion(hash_line() + '\n', return_code=1)
        self.assertFalse(result)

    def test_stale_output_is_not_reused(self):
        out_file = os.path.join(self.tmpdir, 'stale.22000')
        with open(out_file, 'w') as fh:
            fh.write(hash_line() + '\n')

        with patch('wifite.tools.hcxdumptool.Process') as mock_process:
            instance = MagicMock()
            instance.wait.return_value = 1
            mock_process.return_value = instance

            result = HcxPcapngTool.convert_to_hashcat(
                os.path.join(self.tmpdir, 'capture.pcapng'), out_file, bssid=BSSID)

        self.assertFalse(result)
        self.assertFalse(os.path.exists(out_file) and os.path.getsize(out_file) > 0)


class TestHcxDumpToolPassiveFlags(unittest.TestCase):
    def setUp(self):
        Configuration.interface = None

    def _command(self, **kwargs):
        with patch('wifite.tools.hcxdumptool.Configuration.initialize'), \
             patch('wifite.tools.hcxdumptool.Process') as mock_process, \
             patch('wifite.tools.hcxdumptool.time.sleep'):
            instance = MagicMock()
            instance.pid.pid = 12345
            instance.poll.return_value = None
            mock_process.return_value = instance

            tool = HcxDumpTool(interface='wlan0', output_file='/tmp/test.pcapng', **kwargs)
            with tool:
                return mock_process.call_args[0][0]

    def test_disabled_deauth_adds_no_transmit_flags(self):
        command = self._command(enable_deauth=False)
        for flag in HcxDumpToolPassive.PASSIVE_OPTIONS:
            self.assertIn(flag, command)
        self.assertNotIn('-A', command)

    def test_pmf_required_adds_no_transmit_flags(self):
        command = self._command(enable_deauth=True, pmf_required=True)
        for flag in HcxDumpToolPassive.PASSIVE_OPTIONS:
            self.assertIn(flag, command)

    def test_active_capture_keeps_ack_only(self):
        command = self._command(enable_deauth=True)
        self.assertIn('-A', command)
        self.assertNotIn('--associationmax=0', command)

    def test_band_argument_selects_6ghz_channel(self):
        command = self._command(channel=5, band='6')
        self.assertEqual(command[command.index('-c') + 1], '5c')


if __name__ == '__main__':
    unittest.main()