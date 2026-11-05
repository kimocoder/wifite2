#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Hashcat OpenCL device-failure detection and CPU (-D 1) fallback."""

import io
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.tools.hashcat import Hashcat, HashcatCracker

pytestmark = pytest.mark.timeout(30)

HASH_FILE = 'target.22000'
WORDLIST = 'words.txt'

DEVICE_FAILURE = (
    'clCreateCommandQueueWithProperties(): CL_INVALID_QUEUE_PROPERTIES\n'
    'No devices found/left\n'
)


class FakeProcess:
    """Minimal stand-in for wifite.util.process.Process."""

    def __init__(self, returncode, stderr_text=''):
        self._returncode = returncode
        self.pid = SimpleNamespace(
            stdout=io.BytesIO(b''),
            stderr=io.BytesIO(stderr_text.encode()),
        )

    def poll(self):
        return self._returncode

    def wait(self, timeout=None):
        return self._returncode

    def interrupt(self):
        pass


class TestDeviceErrorDetection(unittest.TestCase):
    def test_markers_are_detected(self):
        assert HashcatCracker.is_device_error('No devices found/left')
        assert HashcatCracker.is_device_error(
            'clCreateCommandQueueWithProperties(): CL_INVALID_QUEUE_PROPERTIES')

    def test_ordinary_output_is_not_a_device_error(self):
        assert not HashcatCracker.is_device_error('Exhausted')
        assert not HashcatCracker.is_device_error('')
        assert not HashcatCracker.is_device_error(None)


class TestCpuFallback(unittest.TestCase):
    def setUp(self):
        Hashcat._force_cache = None

    def tearDown(self):
        Hashcat._force_cache = None

    def _cracker(self):
        return HashcatCracker(HASH_FILE, WORDLIST)

    def test_failed_gpu_relaunches_with_cpu_device(self):
        cracker = self._cracker()
        cracker.proc = FakeProcess(255, DEVICE_FAILURE)

        restarted = {'count': 0}

        def fake_start(show_command=False):
            restarted['count'] += 1
            cracker.proc = FakeProcess(None)  # still running
            return cracker.proc

        cracker.start = fake_start

        with patch.object(Hashcat, 'should_use_force',
                          staticmethod(lambda: False)):
            assert cracker.is_finished() is False

        assert restarted['count'] == 1
        assert cracker.cpu_fallback is True
        assert cracker.device_error is False

    def test_cpu_attempt_failure_sets_device_error(self):
        cracker = self._cracker()
        cracker.cpu_fallback = True
        cracker.proc = FakeProcess(255, DEVICE_FAILURE)

        with patch.object(Hashcat, 'should_use_force',
                          staticmethod(lambda: False)):
            assert cracker.is_finished() is True

        assert cracker.device_error is True
        assert cracker.cpu_fallback is True

    def test_clean_exit_is_not_a_device_error(self):
        cracker = self._cracker()
        cracker.proc = FakeProcess(0, 'Status.......: Exhausted\n')

        with patch.object(Hashcat, 'should_use_force',
                          staticmethod(lambda: False)):
            assert cracker.is_finished() is True

        assert cracker.device_error is False
        assert cracker.cpu_fallback is False


class TestBuildCommand(unittest.TestCase):
    def setUp(self):
        Hashcat._force_cache = None

    def tearDown(self):
        Hashcat._force_cache = None

    def test_cpu_flag_present_only_on_fallback(self):
        cracker = HashcatCracker(HASH_FILE, WORDLIST)
        with patch.object(Hashcat, 'should_use_force',
                          staticmethod(lambda: False)):
            default_cmd = cracker._build_command()
            cracker.cpu_fallback = True
            cpu_cmd = cracker._build_command()

        assert '-D' not in default_cmd
        assert '-D' in cpu_cmd
        assert cpu_cmd[cpu_cmd.index('-D') + 1] == '1'
        assert default_cmd[-2:] == [HASH_FILE, WORDLIST]
        assert cpu_cmd[-2:] == [HASH_FILE, WORDLIST]


class ExitCodeClassificationTest(unittest.TestCase):
    def _cracker(self, returncode, stderr=''):
        cracker = HashcatCracker(HASH_FILE, WORDLIST)
        cracker.proc = FakeProcess(returncode, stderr)
        return cracker

    def test_cracked_and_exhausted_are_normal(self):
        for returncode in (0, 1):
            cracker = self._cracker(returncode)
            cracker.is_finished()
            assert cracker.run_error is False

    def test_user_abort_is_not_an_error(self):
        cracker = self._cracker(2)
        cracker.is_finished()
        assert cracker.run_error is False

    def test_error_exit_codes_are_flagged(self):
        for returncode in (3, 4, 255):
            cracker = self._cracker(returncode, 'unrelated hashcat failure')
            cracker.is_finished()
            assert cracker.run_error is True
            assert cracker.returncode == returncode

    def test_signal_death_is_not_an_error(self):
        cracker = self._cracker(-15)
        cracker.is_finished()
        assert cracker.run_error is False

    def test_device_failure_does_not_set_run_error(self):
        cracker = self._cracker(255, DEVICE_FAILURE)
        cracker.cpu_fallback = True
        cracker.is_finished()
        assert cracker.device_error is True
        assert cracker.run_error is False


if __name__ == '__main__':
    unittest.main()