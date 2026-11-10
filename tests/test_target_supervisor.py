import sys
from types import SimpleNamespace

import pytest

from wifite.attack.all import AttackAll
from wifite.config import Configuration
from wifite.config.defaults import initialize_defaults
from wifite.model.target import WPSState


def test_target_timeout_default():
    class Config:
        pass

    initialize_defaults(Config)
    assert Config.target_timeout == 900


def parse_timeout(monkeypatch, value):
    from wifite.args import Arguments
    from wifite.config.parsers.settings import parse_settings_args
    from wifite.model.result import CrackResult

    class Config:
        pass

    initialize_defaults(Config)
    argument = f'--target-timeout={value}' if value.startswith('-') else '--target-timeout'
    argv = ['wifite', argument] if value.startswith('-') else ['wifite', argument, value]
    monkeypatch.setattr(sys, 'argv', argv)
    monkeypatch.setattr(
        CrackResult,
        'cracked_file',
        '.superpowers/nonexistent-target-supervisor-results.json',
    )
    args = Arguments(Config).args
    parse_settings_args(Config, args)
    Config.validate = classmethod(lambda cls: None)
    return Config


def test_target_timeout_zero_is_unlimited(monkeypatch):
    config = parse_timeout(monkeypatch, '0')
    assert config.target_timeout == 0


def test_target_timeout_rejects_negative(monkeypatch):
    from wifite.config.validators import validate

    config = parse_timeout(monkeypatch, '-1')
    with pytest.raises(ValueError, match='target-timeout'):
        validate(config)


class FakeScope:
    def __init__(self, target, timeout):
        self.target = target
        self.timeout = timeout
        self.closed = False

    def close(self):
        self.closed = True


class FakeSupervisor:
    def __init__(self):
        self.scopes = []

    def target_scope(self, target, timeout_seconds):
        scope = FakeScope(target, timeout_seconds)
        self.scopes.append(scope)
        return scope


class FakeTarget:
    def __init__(self, wps):
        self.bssid = 'AA:BB:CC:DD:EE:FF'
        self.essid = 'Fixture'
        self.essid_known = True
        self.channel = 6
        self.encryption = 'WPA2'
        self.authentication = 'PSK'
        self.primary_encryption = 'WPA2'
        self.wps = wps
        self.power = 50
        self.wpa3_info = None


def configure_attacks(monkeypatch, supervisor, include_wps=False, fail=False):
    events = []

    class FakeAttack:
        def __init__(self, target, supervised, name):
            self.target = target
            self.supervised = supervised
            self.name = name
            self.scope = None
            self.success = False
            self.capture_success = False
            self.crack_error = False
            self.crack_result = None

        def set_scope(self, scope):
            self.scope = scope

        def run(self):
            events.append((self.name, self.scope))
            if fail and self.supervised:
                raise ValueError('expected failure')
            return False

    def factory(name, supervised=True):
        return lambda target: FakeAttack(target, supervised, name)

    class FakeWPS:
        def __init__(self, target, pixie_dust=False, null_pin=False):
            self.attack = FakeAttack(target, False, 'wps')

        def __getattr__(self, name):
            return getattr(self.attack, name)

        def set_scope(self, scope):
            self.attack.set_scope(scope)

        def run(self):
            return self.attack.run()

        @staticmethod
        def can_attack_wps():
            return True

    monkeypatch.setattr('wifite.attack.all.AttackPMKID', factory('pmkid'))
    monkeypatch.setattr('wifite.attack.all.AttackWPA', factory('wpa'))
    monkeypatch.setattr('wifite.attack.all.AttackWPS', FakeWPS)
    monkeypatch.setattr(Configuration, 'get_supervisor', classmethod(lambda cls: supervisor), raising=False)
    monkeypatch.setattr(Configuration, 'target_timeout', 900, raising=False)
    for name, value in {
        'use_eviltwin': False,
        'wpa3_only': False,
        'use_pmkid_only': False,
        'dont_use_pmkid': False,
        'wps_only': False,
        'wps_pixie': include_wps,
        'wps_pin': include_wps,
        'verbose': 0,
    }.items():
        monkeypatch.setattr(Configuration, name, value, raising=False)
    return events


def test_scope_starts_at_first_supervised_attack(monkeypatch):
    supervisor = FakeSupervisor()
    events = configure_attacks(monkeypatch, supervisor)

    AttackAll.attack_single(FakeTarget(WPSState.NONE), 0)

    assert len(supervisor.scopes) == 1
    assert events[0][1] is supervisor.scopes[0]


def test_legacy_wps_remains_outside_scope(monkeypatch):
    supervisor = FakeSupervisor()
    events = configure_attacks(monkeypatch, supervisor, include_wps=True)

    AttackAll.attack_single(FakeTarget(WPSState.UNLOCKED), 0)

    wps_events = [scope for name, scope in events if name == 'wps']
    assert wps_events == [None, None, None]
    assert len(supervisor.scopes) == 1
    assert all(scope is supervisor.scopes[0] for name, scope in events if name != 'wps')


def test_scope_is_shared_by_supervised_fallbacks(monkeypatch):
    supervisor = FakeSupervisor()
    configure_attacks(monkeypatch, supervisor)

    AttackAll.attack_single(FakeTarget(WPSState.NONE), 0)

    assert len(supervisor.scopes) == 1
    assert supervisor.scopes[0].closed


def test_scope_closes_after_exception(monkeypatch):
    supervisor = FakeSupervisor()
    configure_attacks(monkeypatch, supervisor, fail=True)

    result = AttackAll.attack_single(FakeTarget(WPSState.NONE), 0)

    assert result is True
    assert len(supervisor.scopes) == 1
    assert supervisor.scopes[0].closed
