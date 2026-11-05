#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""--exitoneapol is only used with a target-BSSID BPF filter."""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration
from wifite.tools.hcxdumptool import HcxDumpTool

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'
BSSID_HEX = '5ce28c23dcb0'


class ExitOnEapolCommandTest(unittest.TestCase):
    def setUp(self):
        HcxDumpTool._bpf_cache = {}

    def tearDown(self):
        HcxDumpTool._bpf_cache = {}

    def _command(self, target_bssid, exitoneapol, bpf_file):
        with patch.object(HcxDumpTool, 'check_tool_pairing',
                          return_value=(True, None)), \
             patch.object(HcxDumpTool, '_install_target_bpf',
                          return_value=bpf_file), \
             patch.object(HcxDumpTool, 'check_version', return_value='8.0.0'), \
             patch.object(Configuration, 'initialize'), \
             patch('wifite.tools.hcxdumptool.time.sleep'), \
             patch('wifite.tools.hcxdumptool.Process') as process_cls:
            HcxDumpTool._bpf_cache = {}
            tool = HcxDumpTool(
                interface='wlan1', channel=1, target_bssid=target_bssid,
                output_file='/tmp/exitoneapol-test.pcapng',
                manage_interface=False, exitoneapol=exitoneapol)
            with tool:
                pass
            return process_cls.call_args[0][0]

    def test_uses_bpf_and_exitoneapol_with_target(self):
        command = self._command(BSSID, 6, '/tmp/target.bpf')

        assert '--bpf=/tmp/target.bpf' in command
        assert '--exitoneapol=6' in command

    def test_skips_exitoneapol_without_bpf(self):
        command = self._command(BSSID, 6, None)

        assert not any(flag.startswith('--exitoneapol') for flag in command)
        assert not any(flag.startswith('--bpf') for flag in command)

    def test_no_exitoneapol_when_not_requested(self):
        command = self._command(BSSID, None, '/tmp/target.bpf')

        assert not any(flag.startswith('--exitoneapol') for flag in command)


class TargetBpfTest(unittest.TestCase):
    def setUp(self):
        HcxDumpTool._bpf_cache = {}
        self.tmpdir = tempfile.TemporaryDirectory()
        self.filter_path = os.path.join(self.tmpdir.name, 'target.bpf')

    def tearDown(self):
        HcxDumpTool._bpf_cache = {}
        self.tmpdir.cleanup()

    def _tool(self):
        return HcxDumpTool.__new__(HcxDumpTool)

    def _compile(self, output):
        process = MagicMock()
        process.stdout.return_value = output
        with patch.object(Configuration, 'temp',
                          return_value=self.filter_path), \
             patch('wifite.tools.hcxdumptool.Process',
                   return_value=process) as process_cls:
            result = self._tool()._install_target_bpf(BSSID)

        return result, process_cls

    def test_compiles_wlan_addr3_filter(self):
        result, process_cls = self._compile('48 0 0 3\n100 0 0 8\n')

        assert result == self.filter_path
        command = process_cls.call_args[0][0]
        assert command[0] == 'hcxdumptool'
        assert command[1] == '--bpfc=wlan addr3 %s' % BSSID_HEX
        with open(self.filter_path) as handle:
            assert '48 0 0 3' in handle.read()

    def test_empty_compile_output_is_rejected(self):
        result, _ = self._compile('   \n')
        assert result is None

    def test_filter_is_cached(self):
        first, process_cls = self._compile('48 0 0 3\n')
        assert first == self.filter_path

        with patch('wifite.tools.hcxdumptool.Process') as second_cls:
            assert self._tool()._install_target_bpf(BSSID) == self.filter_path
        second_cls.assert_not_called()

    def test_compilation_failure_is_ignored(self):
        with patch.object(Configuration, 'temp',
                          return_value=self.filter_path), \
             patch('wifite.tools.hcxdumptool.Process',
                   side_effect=OSError('no hcxdumptool')):
            assert self._tool()._install_target_bpf(BSSID) is None


if __name__ == '__main__':
    unittest.main()