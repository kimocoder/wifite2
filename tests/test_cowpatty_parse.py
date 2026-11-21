#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Cowpatty PSK output parsing."""

from wifite.tools.cowpatty import CowpattyCracker


def _cracker():
    return CowpattyCracker('/tmp/nonexistent.cap', 'wifite-test',
                           '/tmp/nonexistent.txt')


def test_psk_line_strips_closing_quote_and_period():
    cracker = _cracker()
    cracker._parse_line('The PSK is "wifite-test-pass".')
    assert cracker.get_result() == 'wifite-test-pass'


def test_psk_line_without_trailing_period():
    cracker = _cracker()
    cracker._parse_line('The PSK is "wifite-test-pass"')
    assert cracker.get_result() == 'wifite-test-pass'


def test_psk_line_with_spaces():
    cracker = _cracker()
    cracker._parse_line('The PSK is "pass phrase here".')
    assert cracker.get_result() == 'pass phrase here'