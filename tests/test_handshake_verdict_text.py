"""The three handshake validators must not contradict each other."""

import re
from unittest.mock import patch

from wifite.model.handshake import Handshake

BSSID = 'AA:BB:CC:DD:EE:FF'
_MARKUP = re.compile(r'\{[A-Z!+]\}')


def _handshake():
    hs = object.__new__(Handshake)
    hs.capfile = '/tmp/x.cap'
    hs.bssid = BSSID
    hs.essid = 'net'
    return hs


def _printed(mock_pl):
    text = ' '.join(str(call.args[0]) for call in mock_pl.call_args_list)
    return _MARKUP.sub('', text)


def test_complete_four_way_is_reported_complete():
    hs = _handshake()
    with patch('wifite.model.handshake.Tshark.exists', return_value=True), \
         patch('wifite.model.handshake.Tshark.eapol_analysis',
               return_value=([], {BSSID: {1, 2, 3, 4}})), \
         patch('wifite.model.handshake.Color.pl') as pl:
        hs._print_tshark_analysis()

    text = _printed(pl)
    assert 'complete 4-way' in text
    assert 'missing' not in text


def test_partial_names_the_missing_message():
    hs = _handshake()
    with patch('wifite.model.handshake.Tshark.exists', return_value=True), \
         patch('wifite.model.handshake.Tshark.eapol_analysis',
               return_value=([], {BSSID: {1, 2, 3}})), \
         patch('wifite.model.handshake.Color.pl') as pl:
        hs._print_tshark_analysis()

    text = _printed(pl)
    assert 'missing M4' in text
    assert 'crackable partial' in text


def test_pair_without_m1_or_m3_is_not_crackable():
    hs = _handshake()
    with patch('wifite.model.handshake.Tshark.exists', return_value=True), \
         patch('wifite.model.handshake.Tshark.eapol_analysis',
               return_value=([], {BSSID: {2, 4}})), \
         patch('wifite.model.handshake.Color.pl') as pl:
        hs._print_tshark_analysis()

    assert 'not crackable' in _printed(pl)


def test_disagreement_says_which_validator_wifite_trusts():
    hs = _handshake()
    with patch.object(Handshake, 'divine_bssid_and_essid'), \
         patch('wifite.model.handshake.Tshark.exists', return_value=True), \
         patch.object(Handshake, '_print_tshark_analysis', return_value=True), \
         patch('wifite.model.handshake.Process.exists', return_value=False), \
         patch.object(Handshake, 'aircrack_handshakes', return_value=[]), \
         patch('wifite.model.handshake.Color.pl') as pl:
        hs.analyze()

    assert 'trusts' in _printed(pl)