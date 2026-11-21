#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""--cracked/--ignored empty-state messages."""

import unittest
from unittest.mock import patch

from wifite.model.result import CrackResult


class TestCrackResultDisplay(unittest.TestCase):

    def _messages(self, result_type, exists=True, load_all=None):
        with patch('wifite.model.result.os.path.exists', return_value=exists), \
                patch.object(CrackResult, 'load_all', return_value=load_all or []), \
                patch('wifite.model.result.Color.pl') as color:
            CrackResult.display(result_type)
        return '\n'.join(str(call.args[0]) for call in color.call_args_list
                         if call.args)

    def test_missing_file_cracked(self):
        output = self._messages('cracked', exists=False)
        self.assertIn('No cracked results recorded yet', output)
        self.assertNotIn('not found', output)

    def test_missing_file_ignored(self):
        output = self._messages('ignored', exists=False)
        self.assertIn('No ignored results recorded yet', output)
        self.assertNotIn('not found', output)

    def test_empty_file_cracked(self):
        output = self._messages('cracked', exists=True)
        self.assertIn('No cracked results recorded yet', output)

    def test_empty_file_ignored(self):
        output = self._messages('ignored', exists=True)
        self.assertIn('No ignored results recorded yet', output)


if __name__ == '__main__':
    unittest.main()