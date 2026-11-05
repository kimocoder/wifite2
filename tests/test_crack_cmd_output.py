#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""--print-crack-cmd: command printing is opt-in, quoting is shell-safe."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, '..')

from wifite.config import Configuration
from wifite.util import crack

pytestmark = pytest.mark.timeout(30)


class PrintCrackingCommandTest(unittest.TestCase):
    def test_quotes_paths_with_spaces(self):
        with patch('wifite.util.color.Color.pl') as color_pl:
            crack.print_cracking_command(
                'aircrack-ng',
                ['aircrack-ng', '-w', 'my words.txt', '-b', 'AA:BB:CC:DD:EE:FF'])

        message = color_pl.call_args[0][0]
        assert 'aircrack-ng' in message
        assert "'my words.txt'" in message
        assert 'AA:BB:CC:DD:EE:FF' in message


class ShowCommandGatingTest(unittest.TestCase):
    def setUp(self):
        handle, self.wordlist = tempfile.mkstemp(suffix='.txt')
        os.close(handle)

    def tearDown(self):
        os.remove(self.wordlist)

    def _show_command(self, show_cracking_command, verbose):
        hs = {
            'filename': '/tmp/handshake.cap',
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'essid': 'TestNetwork',
        }

        with patch.object(Configuration, 'show_cracking_command',
                          show_cracking_command), \
             patch.object(Configuration, 'verbose', verbose), \
             patch.object(Configuration, 'wordlists', [self.wordlist]), \
             patch.object(Configuration, 'wordlist', self.wordlist), \
             patch('wifite.util.crack.Handshake'), \
             patch('wifite.util.crack.Aircrack.crack_handshake',
                   return_value=None) as crack_fn, \
             patch('wifite.util.crack.Color.pl'):
            crack.CrackHelper.crack_4way(hs, 'aircrack')

        return crack_fn.call_args.kwargs.get('show_command')

    def test_command_is_hidden_by_default(self):
        assert self._show_command(False, 0) is False

    def test_print_crack_cmd_enables_command(self):
        assert self._show_command(True, 0) is True

    def test_verbose_still_enables_command(self):
        assert self._show_command(False, 1) is True


if __name__ == '__main__':
    unittest.main()
