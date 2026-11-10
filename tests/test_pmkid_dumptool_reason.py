"""AttackPMKID must carry hcxdumptool's own reason instead of guessing."""

from types import SimpleNamespace

import wifite.attack.pmkid as pmkid_module
from wifite.attack.pmkid import AttackPMKID

WATCHDOG = 'no packets received (watchdog timeout)'


class FakeDumpTool:
    reason = WATCHDOG

    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def is_running(self):
        return False

    def get_failure_reason(self):
        return type(self).reason


def _bare_attack():
    attack = object.__new__(AttackPMKID)
    attack.target = SimpleNamespace(
        pmf_required=False, channel=6, bssid='AA:BB:CC:DD:EE:FF', band='2.4')
    attack.scope = None
    attack.pcapng_file = '/tmp/pmkid.pcapng'
    attack.keep_capturing = True
    attack._dumptool_died = False
    attack._dumptool_reason = ''
    return attack


def test_dumptool_thread_records_reason(monkeypatch):
    monkeypatch.setattr(pmkid_module, 'HcxDumpTool', FakeDumpTool)

    attack = _bare_attack()
    attack.dumptool_thread()

    assert attack._dumptool_died is True
    assert attack._dumptool_reason == WATCHDOG


def test_dumptool_thread_leaves_reason_empty_when_unknown(monkeypatch):
    class Quiet(FakeDumpTool):
        reason = ''

    monkeypatch.setattr(pmkid_module, 'HcxDumpTool', Quiet)

    attack = _bare_attack()
    attack.dumptool_thread()

    assert attack._dumptool_died is True
    assert attack._dumptool_reason == ''


def test_reason_is_fetched_before_the_died_flag_is_set(monkeypatch):
    """The main loop watches the flag; the reason must already be there."""
    attack = _bare_attack()

    class Checking(FakeDumpTool):
        def get_failure_reason(self):
            assert attack._dumptool_died is False, \
                'reason must be fetched before the exit is announced'
            return WATCHDOG

    monkeypatch.setattr(pmkid_module, 'HcxDumpTool', Checking)

    attack.dumptool_thread()

    assert attack._dumptool_died is True
    assert attack._dumptool_reason == WATCHDOG