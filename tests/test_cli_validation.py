#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""CLI validation: reject negative durations and report config errors cleanly."""

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIFITE = os.path.join(ROOT, 'bin', 'wifite')
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def run(*args):
    result = subprocess.run(
        [sys.executable, WIFITE, *args],
        capture_output=True, text=True, cwd=ROOT, timeout=30,
        stdin=subprocess.DEVNULL,
    )
    return result.returncode, ANSI.sub('', result.stdout + result.stderr)


@unittest.skipUnless(hasattr(os, 'geteuid'), 'requires POSIX')
class TestNegativeDurations(unittest.TestCase):

    def _assert_rejected(self, arg):
        code, output = run('--syscheck', arg)
        self.assertEqual(code, 2, output)
        self.assertIn('must be zero or a positive integer', output)
        self.assertNotIn('Traceback', output)

    def test_pmkid_timeout(self):
        self._assert_rejected('--pmkid-timeout=-1')

    def test_wpa_attack_timeout(self):
        self._assert_rejected('--wpat=-5')

    def test_eviltwin_timeout(self):
        self._assert_rejected('--eviltwin-timeout=-10')

    def test_wpasec_timeout(self):
        self._assert_rejected('--wpasec-timeout=-5')

    def test_alias_also_rejects(self):
        self._assert_rejected('-wpat=-3')


@unittest.skipUnless(os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
                     'requires root for configuration initialization')
class TestConfigErrorsAreClean(unittest.TestCase):

    def _assert_clean_failure(self, *args):
        code, output = run(*args)
        self.assertEqual(code, 1, output)
        self.assertIn('Exiting', output)
        self.assertNotIn('Traceback', output)
        self.assertNotIn('Unexpected Error', output)

    def test_negative_target_timeout(self):
        self._assert_clean_failure('--syscheck', '--target-timeout=-1')

    def test_wpasec_without_key(self):
        self._assert_clean_failure('--syscheck', '--wpasec')

    def test_invalid_eviltwin_port(self):
        self._assert_clean_failure('--syscheck', '--eviltwin', '--eviltwin-port', '99999')

    def test_same_primary_and_secondary(self):
        self._assert_clean_failure(
            '--syscheck', '-i', 'wlan1',
            '--interface-primary', 'wlan1',
            '--interface-secondary', 'wlan1', '--wpa')


if __name__ == '__main__':
    unittest.main()