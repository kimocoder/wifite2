import os
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from wifite.attack.eviltwin import EvilTwin
from wifite.config import Configuration
from wifite.tools.dnsmasq import Dnsmasq
from wifite.tools.hostapd import Hostapd
from wifite.util.client_monitor import ClientMonitor, ClientConnection
from wifite.util.supervisor import (
    RadioProcessSupervisor,
    ServiceHealthError,
    TargetTimeoutExpired,
)


class FakeProcess:
    def __init__(self):
        self.running = True

    def poll(self):
        return None if self.running else 0

    def is_running(self):
        return self.running

    def interrupt(self):
        self.running = False


class FakeScope:
    def __init__(self, tmp_path):
        self.supervisor = self
        self.tmp_path = tmp_path
        self.processes = []
        self.health = []
        self.radio_calls = []
        self.error = None

    def create_log(self, name):
        path = os.path.join(self.tmp_path, f'{name}.log')
        open(path, 'a').close()
        return path

    def spawn(self, command, role, log_path=None):
        process = FakeProcess()
        self.processes.append((process, role, log_path))
        return process

    def register_health(self, name, callback, required=True):
        self.health.append((name, callback, required))

    def check(self):
        if self.error:
            raise self.error

    def sleep(self, seconds):
        self.check()

    def radio(self, interface, role, scope):
        self.radio_calls.append((interface, role))
        @contextmanager
        def lease():
            yield
        return lease()


def make_attack(scope=None):
    target = SimpleNamespace(
        essid='Fixture',
        bssid='AA:BB:CC:DD:EE:FF',
        channel=6,
        clients=[],
    )
    attack = EvilTwin(target, interface_ap='wlan0', interface_deauth='wlan1')
    attack.scope = scope
    attack._install_signal_handlers = lambda: None
    attack._restore_signal_handlers = lambda: None
    attack._cleanup = lambda: None
    return attack


def test_hostapd_and_dnsmasq_share_real_logs_with_monitor(tmp_path, monkeypatch):
    scope = FakeScope(tmp_path)
    monkeypatch.setattr(Configuration, 'temp', lambda name='': os.path.join(tmp_path, name))
    monkeypatch.setattr('wifite.tools.hostapd.time.sleep', lambda _: None)
    monkeypatch.setattr('wifite.tools.dnsmasq.time.sleep', lambda _: None)
    monkeypatch.setattr(Hostapd, '_prepare_interface', lambda self: None)
    monkeypatch.setattr(Dnsmasq, '_setup_routing', lambda self: None)

    hostapd = Hostapd('wlan0', 'Fixture', 6, scope=scope)
    dnsmasq = Dnsmasq('wlan0', scope=scope)
    assert hostapd.start()
    assert dnsmasq.start()
    assert hostapd.log_path == scope.processes[0][2]
    assert dnsmasq.log_path == scope.processes[1][2]
    assert os.path.exists(hostapd.log_path)
    assert os.path.exists(dnsmasq.log_path)

    attack = make_attack(scope)
    attack.hostapd = hostapd
    attack.dnsmasq = dnsmasq
    attack.portal_server = SimpleNamespace(is_running=lambda: True)
    attack._setup_client_monitor(hostapd.log_path, dnsmasq.log_path)
    try:
        assert attack.client_monitor.hostapd_log_path == hostapd.log_path
        assert attack.client_monitor.dnsmasq_log_path == dnsmasq.log_path
    finally:
        attack.client_monitor.stop()


def run_with_result(target):
    result = []
    thread = threading.Thread(target=lambda: result.append(target()), daemon=True)
    thread.start()
    thread.join(1)
    return thread, result


def test_service_death_stops_attack_loop():
    scope = FakeScope('.')
    scope.error = ServiceHealthError('dnsmasq died')
    attack = make_attack(scope)
    attack.running = True
    attack.start_time = time.time()
    attack._handle_deauth = lambda: None
    attack._update_status = lambda: None

    thread, result = run_with_result(attack._monitor_attack_loop)
    attack.running = False

    assert not thread.is_alive()
    assert result == [False]


def test_single_and_dual_loops_check_scope(monkeypatch):
    scope = FakeScope('.')
    scope.error = TargetTimeoutExpired('expired')
    attack = make_attack(scope)
    monkeypatch.setattr(attack, '_show_warning', lambda: True)
    monkeypatch.setattr(attack, '_check_dependencies', lambda: True)
    monkeypatch.setattr(attack, '_check_for_conflicts', lambda: True)
    monkeypatch.setattr(attack, '_get_interface_assignment', lambda: None)
    monkeypatch.setattr(attack, '_setup', lambda: True)
    monkeypatch.setattr(attack, '_handle_deauth', lambda: None)
    monkeypatch.setattr(attack, '_update_status', lambda: None)
    monkeypatch.setattr(attack, '_display_statistics', lambda: None)

    single_thread, single_result = run_with_result(attack.run)
    attack.running = False
    dual_thread, dual_result = run_with_result(attack._monitor_attack_loop)
    attack.running = False

    assert not single_thread.is_alive()
    assert not dual_thread.is_alive()
    assert single_result == [False]
    assert dual_result == [False]


def test_validation_and_deauth_share_secondary_radio(monkeypatch):
    scope = FakeScope('.')
    attack = make_attack(scope)
    attack.adaptive_deauth.is_paused = False
    attack.adaptive_deauth.pause = lambda: None
    attack.adaptive_deauth.resume = lambda: None
    monkeypatch.setattr(Configuration, 'eviltwin_validate_credentials', True)
    monkeypatch.setattr('wifite.attack.eviltwin.Process.exists', lambda _: True)
    monkeypatch.setattr('wifite.tools.airmon.Airmon.set_interface_mode', lambda *args: True)
    monkeypatch.setattr('wifite.attack.eviltwin.time.sleep', lambda _: None)

    class Validator:
        def validate_credentials(self, ssid, password):
            return True, 0.1, None

    attack.credential_validator = Validator()
    assert attack._verify_password('Fixture', 'password123') is True
    monkeypatch.setattr('wifite.attack.eviltwin.Process', lambda *args, **kwargs: FakeProcess())
    attack._send_deauth('FF:FF:FF:FF:FF:FF', 1)

    assert scope.radio_calls == [
        ('wlan1', 'credential-validation'),
        ('wlan1', 'deauth'),
    ]


def test_concurrent_validation_is_serialized(monkeypatch):
    class Interfaces:
        def _get_interface_phy(self, interface):
            return 'phy0'

    supervisor = RadioProcessSupervisor(interface_manager=Interfaces())
    scope = supervisor.target_scope(object(), 10)
    attack = make_attack(scope)
    attack.adaptive_deauth.is_paused = False
    attack.adaptive_deauth.pause = lambda: None
    attack.adaptive_deauth.resume = lambda: None
    monkeypatch.setattr(Configuration, 'eviltwin_validate_credentials', True)
    monkeypatch.setattr('wifite.attack.eviltwin.Process.exists', lambda _: True)
    monkeypatch.setattr('wifite.tools.airmon.Airmon.set_interface_mode', lambda *args: True)

    active = 0
    maximum = 0
    counter_lock = threading.Lock()
    entered = threading.Event()
    release = threading.Event()

    class Validator:
        def validate_credentials(self, ssid, password):
            nonlocal active, maximum
            with counter_lock:
                active += 1
                maximum = max(maximum, active)
            entered.set()
            release.wait(1)
            with counter_lock:
                active -= 1
            return True, 0.1, None

    attack.credential_validator = Validator()
    first = threading.Thread(target=attack._verify_password, args=('Fixture', 'password1'))
    second = threading.Thread(target=attack._verify_password, args=('Fixture', 'password2'))
    first.start()
    assert entered.wait(1)
    second.start()
    release.set()
    first.join(1)
    second.join(1)

    assert not first.is_alive()
    assert not second.is_alive()
    assert maximum == 1


def test_disconnect_callback_runs_outside_client_lock():
    monitor = ClientMonitor()
    client = ClientConnection('AA:BB:CC:DD:EE:FF')
    monitor.clients[client.mac_address] = client
    callback_completed = threading.Event()

    def disconnected(_):
        assert monitor.has_connected_clients() is False
        callback_completed.set()

    monitor.on_client_disconnect = disconnected
    worker = threading.Thread(
        target=monitor._handle_client_disconnect,
        args=(client.mac_address,),
        daemon=True,
    )
    worker.start()
    worker.join(1)

    assert callback_completed.is_set()
    assert not worker.is_alive()
    assert not client.is_connected()
