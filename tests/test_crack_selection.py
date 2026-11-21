#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Validation of the interactive handshake selection for --crack."""

import unittest
from unittest.mock import patch

import pytest

from wifite.util.crack import CrackHelper

pytestmark = pytest.mark.timeout(30)

A = {'filename': '/hs/a.cap', 'bssid': 'AA:BB:CC:DD:EE:01',
     'essid': 'A', 'date': '2026-01-01 00:00:00', 'type': '4-WAY'}
B = {'filename': '/hs/b.cap', 'bssid': 'AA:BB:CC:DD:EE:02',
     'essid': 'B', 'date': '2026-01-01 00:00:00', 'type': '4-WAY'}
HSS = [A, B]


class TestHandshakeSelection(unittest.TestCase):

    def _select(self, inputs, handshakes=HSS):
        with patch('wifite.util.crack.interactive_input',
                   side_effect=inputs) as prompt, \
                patch('wifite.util.crack.Color'):
            result = CrackHelper.get_user_selection(handshakes)
        return result, prompt

    def _essids(self, inputs, handshakes=HSS):
        result, _ = self._select(inputs, handshakes)
        return [h['essid'] for h in result]

    def test_single_index(self):
        self.assertEqual(self._essids(['1']), ['A'])

    def test_multiple_indices_with_spaces(self):
        self.assertEqual(self._essids(['2, 1']), ['B', 'A'])

    def test_range(self):
        self.assertEqual(self._essids(['1-2']), ['A', 'B'])

    def test_all(self):
        self.assertEqual(self._essids(['all']), ['A', 'B'])
        self.assertEqual(self._essids(['ALL']), ['A', 'B'])

    def test_duplicates_are_removed(self):
        self.assertEqual(self._essids(['1,1,1-2']), ['A', 'B'])

    def test_invalid_text_reprompts(self):
        self.assertEqual(self._essids(['foo', '1']), ['A'])

    def test_out_of_range_reprompts(self):
        for bad in ('0', '3', '1-999', '2-1'):
            self.assertEqual(self._essids([bad, '1']), ['A'], bad)

    def test_empty_input_reprompts(self):
        self.assertEqual(self._essids(['', '1']), ['A'])

    def test_partially_invalid_list_reprompts(self):
        self.assertEqual(self._essids(['1,foo', '2']), ['B'])

    def test_no_handshakes_returns_empty_without_prompt(self):
        result, prompt = self._select([], handshakes=[])
        self.assertEqual(result, [])
        prompt.assert_not_called()


if __name__ == '__main__':
    unittest.main()