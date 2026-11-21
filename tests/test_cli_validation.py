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

    def _assert_rejected(self, *args):
        code, output = run('--syscheck', *args)
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

    def test_scan_time(self):
        self._assert_rejected('-p=-1')

    def test_wps_pixie_timeout(self):
        self._assert_rejected('--wps-time=-1')

    def test_pmkid_passive_duration(self):
        self._assert_rejected('--pmkid-passive-duration=-5')

    def test_wep_timeout(self):
        self._assert_rejected('--wept=-1')


@unittest.skipUnless(os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
                     'requires root for configuration initialization')
@unittest.skipUnless(os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
                     'requires root for configuration initialization')
class TestWpasecKeyHandling(unittest.TestCase):

    def test_value_flag_is_rejected(self):
        code, output = run('--syscheck', '--wpasec-key', 'secret')
        self.assertEqual(code, 2, output)
        self.assertIn('unrecognized arguments', output)

    def test_key_file_is_accepted(self):
        import tempfile

        fd, path = tempfile.mkstemp()
        os.write(fd, b'a' * 32 + b'\n')
        os.close(fd)
        try:
            code, output = run('--syscheck', '--wpasec',
                               '--wpasec-key-file', path)
            self.assertEqual(code, 0, output)
            self.assertNotIn('Traceback', output)
        finally:
            os.remove(path)


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

    def test_conflicting_dual_interface_flags(self):
        self._assert_clean_failure(
            '--syscheck', '--dual-interface', '--no-dual-interface')

    def test_conflicting_eviltwin_and_pmkid(self):
        self._assert_clean_failure('--syscheck', '--eviltwin', '--pmkid')

    def test_wpa3_only_with_wpa_filter_warns(self):
        code, output = run('--syscheck', '--wpa3-only', '--wpa')
        self.assertEqual(code, 0, output)
        self.assertIn('--wpa3-only limits attacks to WPA3', output)

    def test_wps_only_with_wpa_filter_is_allowed(self):
        code, output = run('--syscheck', '--wps-only', '--wpa')
        self.assertEqual(code, 0, output)
        self.assertNotIn('Bad Configuration', output)


if __name__ == '__main__':
    unittest.main()