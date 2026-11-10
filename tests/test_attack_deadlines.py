import os
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from wifite.attack.pmkid import AttackPMKID
from wifite.attack.wpa import AttackWPA
from wifite.attack.wpa3 import AttackWPA3SAE
from wifite.config import Configuration
from wifite.util.sae_crack import SAECracker
from wifite.util.supervisor import ServiceHealthError, TargetTimeoutExpired
from wifite.util.wpasec_uploader import WpaSecUploader


class FakeScope:
    def __init__(self, remaining=30, error=None):
        self.supervisor = self
        self.remaining_value = remaining
        self.error = error
        self.check_calls = 0
        self.sleep_calls = []
        self.health = []

    def remaining(self):
        return self.remaining_value

    def check(self):
        self.check_calls += 1
        for name, callback, required in self.health:
            if required and not callback():
                raise ServiceHealthError(f'{name} died')
        if self.error:
            raise self.error

    def sleep(self, seconds):
        self.sleep_calls.append(seconds)
        self.check()

    def register_health(self, name, callback, required=True):
        self.health.append((name, callback, required))

    def clear_health(self):
        self.health.clear()

    @contextmanager
    def radio(self, interface, role, scope):
        yield


def target():
    return SimpleNamespace(
        essid='Fixture',
        essid_known=True,
        bssid='AA:BB:CC:DD:EE:FF',
        channel=6,
        power=50,
        clients=[],
        primary_authentication='PSK',
        wpa_ft=False,
        band=None,
    )


def test_capture_timeout_is_capped_by_target_remaining():
    attack = AttackWPA(target())
    attack.set_scope(FakeScope(remaining=2.5))

    assert attack._cap_timeout(300) == 2.5


def test_capture_loop_checks_scope(monkeypatch):
    scope = FakeScope(error=TargetTimeoutExpired('expired'))
    attack = AttackWPA(target())
    attack.set_scope(scope)
    attack._reuse_shared_capture = lambda: None
    attack.wait_for_target = lambda airodump: airodump
    monkeypatch.setattr(Configuration, 'use_hcxdump', False)
    monkeypatch.setattr(Configuration, 'ignore_old_handshakes', True)
    monkeypatch.setattr(Configuration, 'wpa_attack_timeout', 0.2)
    monkeypatch.setattr(Configuration, 'wpa_deauth_timeout', 1)

    class Airodump:
        def __init__(self, **kwargs):
            self.clients = []
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def find_files(self, endswith):
            return []

    monkeypatch.setattr('wifite.attack.wpa.Airodump', Airodump)
    with pytest.raises(TargetTimeoutExpired):
        attack.capture_handshake()
    assert scope.check_calls > 0


def test_dead_hcxdump_fails_promptly(monkeypatch):
    scope = FakeScope()
    attack = AttackWPA3SAE(target())
    attack.set_scope(scope)
    attack.wpa3_info = {'pmf_status': 'disabled'}
    monkeypatch.setattr(Configuration, 'wpa3_attack_timeout', 0.2)
    monkeypatch.setattr(Configuration, 'wpa_attack_timeout', 0.2)

    class DeadHcx:
        def __init__(self, **kwargs):
            pass
        @staticmethod
        def exists():
            return True
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def is_running(self):
            return False
        def has_new_data(self):
            return False

    monkeypatch.setattr('wifite.tools.hcxdumptool.HcxDumpTool', DeadHcx)
    assert attack.capture_sae_handshake() is None
    assert scope.check_calls > 0


class FakeHashcatCracker:
    instances = []
    STATUS_TIMER_SECONDS = 0.01

    def __init__(self, *args, **kwargs):
        self.finished_checks = 0
        self.closed = False
        self.device_error = False
        self.run_error = False
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def start(self, show_command=False):
        pass

    def is_finished(self):
        self.finished_checks += 1
        return self.finished_checks > 1

    def poll_status(self):
        return {'progress': 0.0, 'speed': '0', 'eta': '0'}

    def get_result(self):
        return None


def test_hashcat_polling_respects_target_deadline(tmp_path, monkeypatch):
    from wifite.util import crack_cache

    wordlist = tmp_path / 'words.txt'
    wordlist.write_text('password\n')
    scope = FakeScope(error=TargetTimeoutExpired('expired'))
    attack = AttackPMKID(target())
    attack.set_scope(scope)
    crack_cache.clear()
    FakeHashcatCracker.instances = []
    monkeypatch.setattr(Configuration, 'wordlist', str(wordlist))
    monkeypatch.setattr(Configuration, 'wordlists', [str(wordlist)])
    monkeypatch.setattr('wifite.attack.pmkid.HashcatCracker', FakeHashcatCracker)
    monkeypatch.setattr('wifite.attack.pmkid.Hashcat.order_wordlists', lambda values: values)

    assert attack.crack_pmkid_file('fixture.22000') is False
    assert scope.check_calls > 0
    assert FakeHashcatCracker.instances[0].closed


def test_finished_capture_health_is_cleared_before_cracking(tmp_path, monkeypatch):
    from wifite.util import crack_cache

    wordlist = tmp_path / 'words.txt'
    wordlist.write_text('password\n')
    scope = FakeScope()
    scope.register_health('hcxdumptool', lambda: False)
    attack = AttackPMKID(target())
    attack.set_scope(scope)
    crack_cache.clear()
    FakeHashcatCracker.instances = []
    monkeypatch.setattr(Configuration, 'wordlist', str(wordlist))
    monkeypatch.setattr(Configuration, 'wordlists', [str(wordlist)])
    monkeypatch.setattr('wifite.attack.pmkid.HashcatCracker', FakeHashcatCracker)
    monkeypatch.setattr('wifite.attack.pmkid.Hashcat.order_wordlists', lambda values: values)

    assert attack.crack_pmkid_file('fixture.22000') is False
    assert scope.health == []
    assert FakeHashcatCracker.instances[0].closed


def test_sae_crack_respects_target_deadline(monkeypatch):
    scope = FakeScope(error=TargetTimeoutExpired('expired'))
    cracker = SAECracker(SimpleNamespace(), wordlist='unused', scope=scope)
    cracker.hash_file = 'fixture.22000'
    FakeHashcatCracker.instances = []
    monkeypatch.setattr('wifite.util.sae_crack.HashcatCracker', FakeHashcatCracker)

    with pytest.raises(TargetTimeoutExpired):
        cracker._run_dictionary_with_progress('unused')
    assert FakeHashcatCracker.instances[0].closed


def test_upload_uses_remaining_timeout(monkeypatch):
    scope = FakeScope(remaining=7)
    uploaded = {}
    monkeypatch.setattr(Configuration, 'wpasec_enabled', True)
    monkeypatch.setattr(Configuration, 'wpasec_api_key', 'fixture-key')
    monkeypatch.setattr(Configuration, 'wpasec_auto_upload', True)
    monkeypatch.setattr(Configuration, 'wpasec_url', 'https://wpa-sec.stanev.org')
    monkeypatch.setattr(Configuration, 'wpasec_timeout', 30)
    monkeypatch.setattr(Configuration, 'wpasec_email', None)
    monkeypatch.setattr(Configuration, 'wpasec_remove_after_upload', False)
    monkeypatch.setattr(WpaSecUploader, 'validate_capture_file', lambda *args: (True, None))
    monkeypatch.setattr('wifite.util.wpasec_uploader.Wlancap2wpasec.exists', lambda: True)

    def upload(**kwargs):
        uploaded.update(kwargs)
        return True, 'uploaded'

    monkeypatch.setattr('wifite.util.wpasec_uploader.Wlancap2wpasec.upload', upload)
    assert WpaSecUploader.upload_capture(
        'fixture.cap', 'AA:BB:CC:DD:EE:FF', 'Fixture', scope=scope)
    assert uploaded['timeout'] == 7


def test_deauth_round_is_capped_by_deadline(monkeypatch):
    class DeadlineScope(FakeScope):
        def check(self):
            self.check_calls += 1
            if self.check_calls > 1:
                raise TargetTimeoutExpired('expired')

    scope = DeadlineScope()
    attack = AttackWPA(target())
    attack.set_scope(scope)
    attack.clients = ['11:22:33:44:55:66']
    attack.deauth_interface = 'wlan1'
    calls = []
    monkeypatch.setattr(Configuration, 'no_deauth', False)
    monkeypatch.setattr(
        'wifite.attack.wpa.Aireplay.deauth',
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with pytest.raises(TargetTimeoutExpired):
        attack._deauth_dual(attack.target)
    assert len(calls) == 1


def test_error_recovery_preserves_unrelated_processes(monkeypatch):
    from wifite.util.process import Process

    monkeypatch.setattr(Configuration, 'existing_commands', {})
    attack = AttackWPA(target())
    process = Process(['sleep', '30'], devnull=True)
    try:
        with pytest.raises(OSError):
            with attack._error_recovery_context('fixture'):
                raise OSError(24, 'too many open files')
        assert process.is_running()
    finally:
        process.force_kill()
        process.cleanup()
