"""The message a user gets when an hcxdumptool capture ends early."""

from wifite.attack.wpa import _hcxdumptool_stop_hint

EAPOL_HINT = 'exited on EAPOL but no crackable handshake was found'


def test_a_known_reason_is_shown_as_is():
    assert _hcxdumptool_stop_hint(
        'no packets received (watchdog timeout)', exitoneapol=6) == \
        'no packets received (watchdog timeout)'


def test_exitoneapol_without_a_handshake_is_named():
    """A successful EAPOL exit must not read as an unexplained failure."""
    assert _hcxdumptool_stop_hint('', exitoneapol=6) == EAPOL_HINT


def test_no_reason_and_no_exitoneapol_stays_empty():
    assert _hcxdumptool_stop_hint('', exitoneapol=None) == ''