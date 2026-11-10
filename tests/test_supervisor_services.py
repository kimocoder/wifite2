import os
import sys

import pytest

from wifite.config import Configuration


class FakeInterfaces:
    def _get_interface_phy(self, interface):
        return 'unknown'


def make_scope(tmp_path, monkeypatch, timeout=30):
    from wifite.util.supervisor import RadioProcessSupervisor

    monkeypatch.setattr(
        Configuration,
        'temp',
        lambda subfile='': os.path.join(tmp_path, subfile),
    )
    supervisor = RadioProcessSupervisor(interface_manager=FakeInterfaces())
    return supervisor.target_scope(object(), timeout)


def test_noisy_service_does_not_block(tmp_path, monkeypatch):
    scope = make_scope(tmp_path, monkeypatch)
    try:
        log_path = scope.create_log('noisy')
        process = scope.spawn(
            [
                sys.executable,
                '-c',
                "import sys; sys.stdout.write('x' * 2000000); "
                "sys.stderr.write('e' * 2000000)",
            ],
            role='noisy-service',
            log_path=log_path,
        )
        process.pid.wait(timeout=10)
        scope.close()

        assert process.poll() == 0
        assert os.path.getsize(log_path) == 4000000
    finally:
        scope.close()


def test_service_log_is_owner_only(tmp_path, monkeypatch):
    scope = make_scope(tmp_path, monkeypatch)
    try:
        log_path = scope.create_log('hostapd')
        process = scope.spawn(
            [sys.executable, '-c', "print('service output')"],
            role='hostapd',
            log_path=log_path,
        )
        process.pid.wait(timeout=10)

        assert os.stat(log_path).st_mode & 0o777 == 0o600
        with open(log_path) as handle:
            assert 'service output' in handle.read()
    finally:
        scope.close()


def test_dead_required_service_fails_check(tmp_path, monkeypatch):
    from wifite.util.supervisor import ServiceHealthError

    scope = make_scope(tmp_path, monkeypatch)
    scope.register_health('dnsmasq', lambda: False)
    with pytest.raises(ServiceHealthError, match='dnsmasq'):
        scope.check()
    scope.close()


def test_healthy_services_pass(tmp_path, monkeypatch):
    scope = make_scope(tmp_path, monkeypatch)
    scope.register_health('hostapd', lambda: True)
    scope.register_health('optional-portal', lambda: False, required=False)

    scope.check()
    scope.close()


def test_scope_close_releases_log_descriptors(tmp_path, monkeypatch):
    scope = make_scope(tmp_path, monkeypatch)
    log_path = scope.create_log('dnsmasq')
    process = scope.spawn(
        [sys.executable, '-c', "print('done')"],
        role='dnsmasq',
        log_path=log_path,
    )
    process.pid.wait(timeout=10)
    handles = list(scope._log_handles)

    scope.close()

    assert handles
    assert all(handle.closed for handle in handles)


def test_hcxdumptool_uses_scope_log_and_health_lifecycle(tmp_path, monkeypatch):
    from wifite.tools.hcxdumptool import HcxDumpTool

    class FakeProcess:
        def poll(self):
            return None

        def interrupt(self):
            self.stopped = True

        def stop_owned(self):
            self.group_stopped = True
            return True

    class RecordingScope:
        def __init__(self):
            self.spawned = []
            self.unregistered = []
            self.log_path = str(tmp_path / 'hcxdumptool.log')

        def create_log(self, name):
            self.log_name = name
            open(self.log_path, 'a').close()
            return self.log_path

        def spawn(self, command, role, log_path=None):
            process = FakeProcess()
            self.spawned.append((command, role, log_path))
            return process

        def unregister_health(self, name):
            self.unregistered.append(name)

    from wifite.model.result import CrackResult

    scope = RecordingScope()
    monkeypatch.setattr(sys, 'argv', ['wifite'])
    monkeypatch.setattr(Configuration, 'interface', 'wlan0')
    monkeypatch.setattr(
        CrackResult,
        'cracked_file',
        str(tmp_path / 'nonexistent-cracked-results.json'),
    )
    monkeypatch.setattr(
        HcxDumpTool,
        'check_tool_pairing',
        classmethod(lambda cls: (True, '')),
    )
    monkeypatch.setattr('wifite.tools.hcxdumptool.time.sleep', lambda _: None)

    dumper = HcxDumpTool(
        interface='wlan0',
        output_file=str(tmp_path / 'capture.pcapng'),
        manage_interface=False,
        scope=scope,
    )
    with dumper:
        process = dumper.proc
        assert dumper.log_path == scope.log_path
        assert scope.log_name == 'hcxdumptool'
        assert scope.spawned[0][1] == 'hcxdumptool'
        assert scope.spawned[0][2] == scope.log_path
        assert os.path.exists(scope.log_path)

    assert process.group_stopped
    assert scope.unregistered == ['hcxdumptool']
