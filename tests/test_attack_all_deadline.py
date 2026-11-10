from types import SimpleNamespace

from wifite.attack import all as attack_all
from wifite.config import Configuration
from wifite.model.target import WPSState
from wifite.util.supervisor import TargetTimeoutExpired


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


class DeadlineAttack:
    supervised = False
    capture_success = True
    crack_error = False
    instances = []

    def __init__(self, target):
        self.target = target
        self.ran = False
        self.success = False
        self.__class__.instances.append(self)

    def run(self):
        self.ran = True
        raise TargetTimeoutExpired('expired')


def test_deadline_breaks_attack_chain(monkeypatch):
    monkeypatch.setattr(attack_all, 'AttackPMKID', DeadlineAttack)
    monkeypatch.setattr(attack_all, 'AttackWPA', DeadlineAttack)
    for attr, value in dict(
        use_eviltwin=False,
        wps_only=False,
        use_pmkid_only=False,
        dont_use_pmkid=False,
        wpa3_only=False,
        wpa3_force_sae=False,
    ).items():
        monkeypatch.setattr(Configuration, attr, value)

    DeadlineAttack.instances = []

    assert attack_all.AttackAll.attack_single(target(), 0) is True

    # The chain is [PMKID, WPA]: the first attack raised the deadline and
    # the second must never run.
    assert len(DeadlineAttack.instances) == 2
    assert DeadlineAttack.instances[0].ran is True
    assert DeadlineAttack.instances[1].ran is False
