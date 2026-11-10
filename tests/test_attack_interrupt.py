from types import SimpleNamespace

import pytest

from wifite.attack import all as attack_all
from wifite.attack.all import Answer, AttackAll
from wifite.config import Configuration
from wifite.model.target import WPSState


@pytest.fixture(autouse=True)
def reset_interrupt_flag():
    Configuration.interrupt_requested = False
    yield
    Configuration.interrupt_requested = False


def target():
    return SimpleNamespace(
        essid='Fixture',
        essid_known=True,
        bssid='AA:BB:CC:DD:EE:FF',
        channel=6,
        power=50,
        clients=[],
        encryption='WPA2',
        primary_encryption='WPA2',
        primary_authentication='PSK',
        authentication='PSK',
        wps=WPSState.LOCKED,
        wpa3_info=None,
        wpa_ft=False,
        band=None,
    )


class AbsorbingAttack:
    """Simulates an attack phase that absorbs the interrupt internally:
    it sets the flag (as the SIGINT/SIGTERM handler would) and returns
    normally instead of letting KeyboardInterrupt propagate.
    """

    supervised = False
    capture_success = False
    crack_error = False
    instances = []

    def __init__(self, target):
        self.target = target
        self.ran = False
        self.success = False
        self.__class__.instances.append(self)

    def run(self):
        self.ran = True
        Configuration.interrupt_requested = True
        return False


class PlainAttack(AbsorbingAttack):
    def run(self):
        self.ran = True
        return False


@pytest.fixture
def wpa_chain(monkeypatch):
    monkeypatch.setattr(attack_all, 'AttackPMKID', AbsorbingAttack)
    monkeypatch.setattr(attack_all, 'AttackWPA', PlainAttack)
    for attr, value in dict(
        use_eviltwin=False,
        wps_only=False,
        use_pmkid_only=False,
        dont_use_pmkid=False,
        wpa3_only=False,
        wpa3_force_sae=False,
        attack_max=0,
        infinite_mode=False,
    ).items():
        monkeypatch.setattr(Configuration, attr, value)
    AbsorbingAttack.instances = []
    PlainAttack.instances = []


def test_absorbed_interrupt_stops_attack_chain(wpa_chain, monkeypatch):
    # The first phase absorbs the signal; the chain must not start the
    # next phase. With ExitOrReturn the target loop stops as well.
    monkeypatch.setattr(AttackAll, 'user_wants_to_continue',
                        staticmethod(lambda *a, **k: Answer.ExitOrReturn))

    assert AttackAll.attack_single(target(), 0) is False

    assert AbsorbingAttack.instances[0].ran is True
    assert PlainAttack.instances[0].ran is False


def test_user_continue_clears_flag_and_resumes_chain(wpa_chain, monkeypatch):
    monkeypatch.setattr(AttackAll, 'user_wants_to_continue',
                        staticmethod(lambda *a, **k: Answer.Continue))

    assert AttackAll.attack_single(target(), 0) is True

    # Explicit "continue" supersedes the interrupt: flag cleared and the
    # next phase ran.
    assert Configuration.interrupt_requested is False
    assert PlainAttack.instances[0].ran is True


def test_pending_interrupt_skips_remaining_targets(wpa_chain, monkeypatch):
    Configuration.interrupt_requested = True

    attacked = AttackAll.attack_multiple([target(), target()])

    assert attacked == 0
    assert AbsorbingAttack.instances == []


def test_sigterm_handler_sets_flag_and_raises():
    from wifite.wifite import sigterm_handler

    with pytest.raises(KeyboardInterrupt):
        sigterm_handler(None, None)
    assert Configuration.interrupt_requested is True


def test_sigint_handler_sets_flag_and_raises():
    from wifite.wifite import sigint_handler

    with pytest.raises(KeyboardInterrupt):
        sigint_handler(None, None)
    assert Configuration.interrupt_requested is True
