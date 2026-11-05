#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Proactive OpenCL backend detection and CPU-first wordlist ordering."""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.tools.hashcat import Hashcat, HashcatCracker

pytestmark = pytest.mark.timeout(30)

RUSTICL_FAILURE = (
    'Rusticl warning: Patched Mesa libclc not detected.\n'
    'clCreateCommandQueue(): CL_INVALID_QUEUE_PROPERTIES\n'
)

HEALTHY = (
    'OpenCL Platform ID #1\n'
    '  Backend Device ID #01\n'
    '    Type...........: GPU\n'
)


class BackendProbeTest(unittest.TestCase):
    def setUp(self):
        Hashcat._backend_probe = None
        Hashcat._force_cache = None
        Hashcat._cpu_notice_shown = False

    def tearDown(self):
        Hashcat._backend_probe = None
        Hashcat._force_cache = None
        Hashcat._cpu_notice_shown = False

    def _probe(self, stdout, stderr, exists=True):
        fake = MagicMock()
        fake.exists.return_value = exists
        fake.return_value.get_output.return_value = (stdout, stderr)
        with patch('wifite.tools.hashcat.Process', fake):
            return Hashcat.probe_backend()

    def test_rusticl_queue_failure_prefers_cpu(self):
        assert self._probe('', RUSTICL_FAILURE)['prefer_cpu'] is True

    def test_no_usable_device_prefers_cpu(self):
        assert self._probe(
            '2 device(s) were found and none of them is usable for this run.',
            '')['prefer_cpu'] is True

    def test_healthy_gpu_keeps_gpu(self):
        assert self._probe(HEALTHY, '')['prefer_cpu'] is False

    def test_missing_hashcat_does_not_prefer_cpu(self):
        assert self._probe('', '', exists=False)['prefer_cpu'] is False

    def test_probe_is_cached(self):
        assert self._probe('', RUSTICL_FAILURE)['prefer_cpu'] is True
        fake = MagicMock()
        with patch('wifite.tools.hashcat.Process', fake):
            assert Hashcat.prefer_cpu_device() is True
        fake.assert_not_called()


class WordlistOrderingTest(unittest.TestCase):
    def setUp(self):
        Hashcat._backend_probe = None

    def tearDown(self):
        Hashcat._backend_probe = None

    def test_cpu_backend_orders_smallest_first(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            large = os.path.join(tmpdir, 'large.txt')
            small = os.path.join(tmpdir, 'small.txt')
            with open(large, 'wb') as handle:
                handle.write(b'x' * 1000)
            with open(small, 'wb') as handle:
                handle.write(b'x' * 10)

            with patch.object(Hashcat, 'prefer_cpu_device', return_value=True):
                assert Hashcat.order_wordlists([large, small]) == [small, large]

    def test_gpu_backend_keeps_user_order(self):
        with patch.object(Hashcat, 'prefer_cpu_device', return_value=False):
            assert Hashcat.order_wordlists(['b', 'a']) == ['b', 'a']


class StartUsesCpuDirectlyTest(unittest.TestCase):
    def setUp(self):
        Hashcat._backend_probe = None
        Hashcat._force_cache = None
        Hashcat._cpu_notice_shown = False

    def tearDown(self):
        Hashcat._backend_probe = None
        Hashcat._force_cache = None
        Hashcat._cpu_notice_shown = False

    def test_start_adds_cpu_device_without_failed_attempt(self):
        cracker = HashcatCracker('target.22000', 'words.txt')
        launched = []

        def fake_process(command, *args, **kwargs):
            launched.append(command)
            return MagicMock()

        with patch.object(Hashcat, 'probe_backend',
                          return_value={'prefer_cpu': True, 'reason': 'broken'}), \
             patch.object(Hashcat, 'should_use_force',
                          staticmethod(lambda: False)), \
             patch.object(HashcatCracker, '_read_output'), \
             patch('wifite.tools.hashcat.Process', side_effect=fake_process):
            cracker.start()

        assert cracker.cpu_fallback is True
        assert len(launched) == 1
        command = launched[0]
        assert '-D' in command
        assert command[command.index('-D') + 1] == '1'


if __name__ == '__main__':
    unittest.main()