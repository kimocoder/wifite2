#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Target selection must tolerate the input the prompt advertises."""

from unittest.mock import patch

import pytest

from wifite.util.scanner import Scanner


def make_scanner(count=12):
    scanner = object.__new__(Scanner)
    scanner.targets = [f't{i}' for i in range(1, count + 1)]
    scanner.err_msg = None
    scanner.use_tui = False
    return scanner


def select(text, retry=None):
    scanner = make_scanner()
    answers = [text]
    if retry is not None:
        answers.append(retry)
    with patch('wifite.util.input.interactive_input', side_effect=answers), \
            patch.object(Scanner, 'print_targets'), \
            patch('wifite.util.scanner.Color'):
        return scanner._prompt_user_for_targets_classic()


@pytest.mark.parametrize('text, expected', [
    ('6,10,11,12', ['t6', 't10', 't11', 't12']),
    ('6-10', ['t6', 't7', 't8', 't9', 't10']),
    ('6-10-11-12', ['t6', 't10', 't11', 't12']),
    (' 7 , 9 ', ['t7', 't9']),
    ('1-2,2', ['t1', 't2']),
    ('all', [f't{i}' for i in range(1, 13)]),
])
def test_selection_is_parsed(text, expected):
    assert select(text) == expected


@pytest.mark.parametrize('text', [
    '0', '13', '11-6', '3-', '-3', 'abc', '1--2', '6-10-11-12-',
])
def test_invalid_selection_retries_until_a_valid_answer(text):
    assert select(text, retry='all') == [f't{i}' for i in range(1, 13)]
