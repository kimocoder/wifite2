import subprocess
import threading
from unittest.mock import MagicMock, mock_open, patch

import pytest

from wifite.util.interface_manager import InterfaceManager


IFACE = 'wlan0'
ORIGINAL_MAC = '00:11:22:33:44:55'
NEW_MAC = '66:77:88:99:AA:BB'


class FakeSystem:
    def __init__(self):
        self.mode = 'managed'
        self.channel = 1
        self.mac = ORIGINAL_MAC
        self.ips = ['10.0.0.2/24']
        self.up = True
        self.ifindex = 10
        self.promisc = False
        self.allmulti = False
        self.forwarding = 0
        self.commands = []
        self.forwarding_writes = []
        self.fail_next = None
        self.ignore_next = None

    @staticmethod
    def _result(command, returncode=0):
        return subprocess.CompletedProcess(command, returncode, '', 'simulated failure' if returncode else '')

    def run(self, command, timeout=5):
        command = list(command)
        self.commands.append(command)

        if self.fail_next and self.fail_next(command):
            self.fail_next = None
            return self._result(command, 1)
        if self.ignore_next and self.ignore_next(command):
            self.ignore_next = None
            return self._result(command)

        if command[:3] == ['iw', 'dev', IFACE] and command[3:5] == ['set', 'type']:
            mode = command[5]
            self.mode = {'__ap': 'AP', 'ibss': 'ad-hoc'}.get(mode, mode)
        elif command[:3] == ['iw', 'dev', IFACE] and command[3:5] == ['set', 'channel']:
            self.channel = int(command[5])
        elif command[:3] == ['ip', 'link', 'set'] and command[3] == IFACE:
            self.up = command[4] == 'up'
        elif command[:4] == ['ip', 'link', 'set', 'dev'] and command[4:6] == [IFACE, 'address']:
            self.mac = command[6].upper()
        elif command[:4] == ['ip', 'link', 'set', 'dev'] and command[4:6] == [IFACE, 'promisc']:
            self.promisc = command[6] == 'on'
        elif command[:4] == ['ip', 'link', 'set', 'dev'] and command[4:6] == [IFACE, 'allmulticast']:
            self.allmulti = command[6] == 'on'
        elif command[:3] == ['ip', 'addr', 'add']:
            address = command[3]
            if address not in self.ips:
                self.ips.append(address)
        elif command[:3] == ['ip', 'addr', 'del']:
            address = command[3]
            if address in self.ips:
                self.ips.remove(address)

        return self._result(command)

    def read_forwarding(self):
        return self.forwarding

    def write_forwarding(self, value):
        self.forwarding_writes.append(value)
        self.forwarding = value
        return True


@pytest.fixture
def system():
    return FakeSystem()


@pytest.fixture
def manager(system):
    instance = InterfaceManager()
    patches = [
        patch.object(InterfaceManager, '_get_interface_mode', side_effect=lambda _iface: system.mode),
        patch.object(InterfaceManager, '_get_interface_channel', side_effect=lambda _iface: system.channel),
        patch.object(InterfaceManager, '_get_interface_mac', side_effect=lambda _iface: system.mac),
        patch.object(InterfaceManager, '_is_interface_up', side_effect=lambda _iface: system.up),
        patch.object(InterfaceManager, '_get_interface_addresses', side_effect=lambda _iface: list(system.ips), create=True),
        patch.object(InterfaceManager, '_get_interface_ifindex', side_effect=lambda _iface: system.ifindex, create=True),
        patch.object(InterfaceManager, '_get_interface_flags',
                     side_effect=lambda _iface: ((0x100 if system.promisc else 0) |
                                                 (0x200 if system.allmulti else 0)),
                     create=True),
        patch.object(InterfaceManager, '_read_ip_forwarding', side_effect=system.read_forwarding, create=True),
        patch.object(InterfaceManager, '_write_ip_forwarding', side_effect=system.write_forwarding, create=True),
        patch('wifite.util.interface_manager.Process.run_simple', side_effect=system.run),
    ]
    for patcher in patches:
        patcher.start()
    try:
        yield instance
    finally:
        instance.interface_states.clear()
        instance.managed_interfaces.clear()
        if hasattr(instance, '_forwarding_state'):
            instance._forwarding_state = None
        for patcher in reversed(patches):
            patcher.stop()


def mode_commands(system, mode):
    return [command for command in system.commands if command[:5] == ['iw', 'dev', IFACE, 'set', 'type'] and command[5] == mode]


def test_snapshot_records_complete_original_state_before_writes(manager, system):
    assert manager._save_interface_state(IFACE)
    state = manager.interface_states[IFACE]

    assert state.original_mode == 'managed'
    assert state.original_channel == 1
    assert state.original_mac == ORIGINAL_MAC
    assert state.original_ips == ['10.0.0.2/24']
    assert state.original_up is True
    assert state.original_ifindex == 10
    assert state.original_promisc is False
    assert state.original_allmulti is False
    assert system.commands == []


def test_incomplete_snapshot_prevents_mutation(manager, system):
    system.mac = 'unknown'

    assert not manager.set_interface_mode(IFACE, 'monitor')
    assert system.mode == 'managed'
    assert system.commands == []
    assert IFACE not in manager.interface_states


def test_mode_mutation_executes_once_and_verifies(manager, system):
    assert manager.set_interface_mode(IFACE, 'monitor')

    assert system.mode == 'monitor'
    assert len(mode_commands(system, 'monitor')) == 1
    assert ['ip', 'link', 'set', IFACE, 'down'] in system.commands
    assert ['ip', 'link', 'set', IFACE, 'up'] in system.commands


def test_mode_command_failure_is_not_reported_as_success(manager, system):
    system.fail_next = lambda command: command[:5] == ['iw', 'dev', IFACE, 'set', 'type']

    with patch('wifite.util.interface_manager.log_info') as log_info:
        assert not manager.set_interface_mode(IFACE, 'monitor')

    assert system.mode == 'managed'
    assert not any('SUCCESS' in str(call) for call in log_info.call_args_list)


def test_mode_readback_mismatch_fails(manager, system):
    system.ignore_next = lambda command: command[:5] == ['iw', 'dev', IFACE, 'set', 'type']

    assert not manager.set_interface_mode(IFACE, 'monitor')
    assert system.mode == 'managed'


def test_channel_mutation_executes_once_and_verifies(manager, system):
    assert manager.set_interface_channel(IFACE, 6)

    assert system.channel == 6
    assert system.commands == [['iw', 'dev', IFACE, 'set', 'channel', '6']]


def test_channel_readback_mismatch_fails(manager, system):
    system.ignore_next = lambda command: 'channel' in command

    assert not manager.set_interface_channel(IFACE, 6)
    assert system.channel == 1


def test_mac_mutation_restores_up_and_verifies(manager, system):
    assert manager.set_interface_mac(IFACE, NEW_MAC)

    assert system.mac == NEW_MAC
    assert system.up is True
    assert ['ip', 'link', 'set', 'dev', IFACE, 'address', NEW_MAC] in system.commands


def test_ip_mutation_uses_address_diff_not_flush(manager, system):
    system.ips = ['10.0.0.2/24', '10.0.0.3/24']

    assert manager.set_interface_addresses(IFACE, ['192.168.100.1/24'])

    assert system.ips == ['192.168.100.1/24']
    assert ['ip', 'addr', 'del', '10.0.0.2/24', 'dev', IFACE] in system.commands
    assert ['ip', 'addr', 'del', '10.0.0.3/24', 'dev', IFACE] in system.commands
    assert ['ip', 'addr', 'add', '192.168.100.1/24', 'dev', IFACE] in system.commands
    assert not any('flush' in command for command in system.commands)


def test_up_mutation_verifies_readback(manager, system):
    assert manager.set_interface_up(IFACE, False)
    assert system.up is False
    assert system.commands == [['ip', 'link', 'set', IFACE, 'down']]


def test_cleanup_restores_every_field_changed_by_this_run(manager, system):
    assert manager.set_interface_mode(IFACE, 'monitor')
    assert manager.set_interface_channel(IFACE, 11)
    assert manager.set_interface_mac(IFACE, NEW_MAC)
    assert manager.set_interface_addresses(IFACE, ['192.168.100.1/24'])
    assert manager.set_interface_up(IFACE, False)

    assert manager.cleanup_all() == 1
    assert system.mode == 'managed'
    assert system.channel == 1
    assert system.mac == ORIGINAL_MAC
    assert system.ips == ['10.0.0.2/24']
    assert system.up is True
    assert IFACE not in manager.interface_states


def test_preexisting_monitor_is_not_torn_down_without_mutation(manager, system):
    system.mode = 'monitor'
    system.up = False

    assert manager.set_interface_mode(IFACE, 'monitor')
    assert manager.cleanup_all() == 0
    assert system.mode == 'monitor'
    assert system.up is False
    assert system.commands == []


def test_cleanup_preserves_externally_added_ip_addresses(manager, system):
    assert manager.set_interface_addresses(IFACE, ['192.168.100.1/24'])
    system.ips.append('172.16.0.10/24')

    assert manager.restore_interface(IFACE)
    assert set(system.ips) == {'10.0.0.2/24', '172.16.0.10/24'}


def test_forwarding_already_enabled_is_not_claimed(manager, system):
    system.forwarding = 1

    assert manager.set_ip_forwarding(True)
    assert system.forwarding_writes == []
    assert manager.cleanup_all() == 0
    assert system.forwarding == 1


def test_forwarding_is_restored_to_original_value(manager, system):
    assert manager.set_ip_forwarding(True)
    assert system.forwarding == 1

    manager.cleanup_all()

    assert system.forwarding == 0
    assert system.forwarding_writes == [1, 0]


def test_forwarding_restore_does_not_overwrite_external_change(manager, system):
    assert manager.set_ip_forwarding(True)
    system.forwarding = 0

    manager.cleanup_all()

    assert system.forwarding == 0
    assert system.forwarding_writes == [1]


def test_interface_identity_mismatch_prevents_restoration(manager, system):
    assert manager.set_interface_mode(IFACE, 'monitor')
    system.ifindex = 99

    assert not manager.restore_interface(IFACE)
    assert system.mode == 'monitor'
    assert IFACE in manager.interface_states


def test_failed_restore_retains_record_and_retries(manager, system):
    assert manager.set_interface_mode(IFACE, 'monitor')
    system.fail_next = lambda command: command == ['iw', 'dev', IFACE, 'set', 'type', 'managed']

    assert manager.cleanup_all() == 0
    assert IFACE in manager.interface_states
    assert system.mode == 'monitor'

    assert manager.cleanup_all() == 1
    assert system.mode == 'managed'
    assert IFACE not in manager.interface_states


def test_concurrent_cleanup_restores_once(manager, system):
    assert manager.set_interface_mode(IFACE, 'monitor')
    results = []
    barrier = threading.Barrier(2)

    def clean():
        barrier.wait()
        results.append(manager.cleanup_all())

    threads = [threading.Thread(target=clean) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert sorted(results) == [0, 1]
    assert len(mode_commands(system, 'managed')) == 1
    assert system.mode == 'managed'


def test_restore_repairs_out_of_band_monitor_mac_and_flags(manager, system):
    """hcxdumptool changes mode/MAC/flags behind the ledger's back."""
    assert manager.set_interface_mode(IFACE, 'monitor')

    # Simulate hcxdumptool: no owner calls, just a mutated radio.
    system.mode = 'monitor'
    system.mac = NEW_MAC
    system.promisc = True
    system.allmulti = True

    assert manager.restore_interface(IFACE)
    assert system.mode == 'managed'
    assert system.mac == ORIGINAL_MAC
    assert system.promisc is False
    assert system.allmulti is False
    assert IFACE not in manager.interface_states


def test_restore_reports_partial_when_flag_readback_disagrees(manager, system):
    assert manager._save_interface_state(IFACE)
    system.promisc = True
    # The command reports success but the flag never clears.
    system.ignore_next = lambda command: 'promisc' in command

    with patch('wifite.util.interface_manager.log_info') as log_info:
        assert not manager.restore_interface(IFACE)

    assert IFACE in manager.interface_states
    assert not any('SUCCESS' in str(call) for call in log_info.call_args_list)


def test_handover_uses_live_state_without_snapshot(manager, system):
    system.mode = 'monitor'

    assert manager.hand_over_monitor(IFACE)
    assert system.mode == 'managed'
    assert IFACE not in manager.interface_states

    assert manager.rearm_monitor(IFACE)
    assert system.mode == 'monitor'


def test_handover_tracks_state_when_managed(manager, system):
    assert manager.set_interface_mode(IFACE, 'monitor')

    assert manager.hand_over_monitor(IFACE)
    assert system.mode == 'managed'
    assert manager.interface_states[IFACE].current_mode == 'managed'

    assert manager.rearm_monitor(IFACE)
    assert system.mode == 'monitor'


class TestInterfaceAdminState:
    def test_up_state_uses_iff_up_not_operstate(self):
        with patch('builtins.open', mock_open(read_data='0x1003\n')):
            assert InterfaceManager._is_interface_up(IFACE) is True
        with patch('builtins.open', mock_open(read_data='0x1002\n')):
            assert InterfaceManager._is_interface_up(IFACE) is False

    def test_up_state_falls_back_to_link_flags(self):
        with patch('builtins.open', side_effect=OSError), \
                patch('wifite.util.interface_manager.Process') as process:
            process.return_value.stdout.return_value = (
                '3: wlan0: <BROADCAST,UP,LOWER_UP> mtu 1500 state DOWN')
            assert InterfaceManager._is_interface_up(IFACE) is True


class TestServiceCleanupPaths:
    def test_hostapd_cleanup_restores_through_owner(self):
        from wifite.config import Configuration
        from wifite.tools.hostapd import Hostapd

        hostapd = Hostapd.__new__(Hostapd)
        hostapd.interface = IFACE
        hostapd.running = False
        hostapd.process = None
        hostapd.config_file = None

        owner = MagicMock()
        owner.restore_interface.return_value = True
        with patch.object(Configuration, 'get_interface_manager', return_value=owner):
            hostapd.cleanup()

        owner.restore_interface.assert_called_once_with(IFACE)

    def test_dnsmasq_routing_uses_owner_forwarding(self):
        from wifite.config import Configuration
        from wifite.tools.dnsmasq import Dnsmasq

        dnsmasq = Dnsmasq.__new__(Dnsmasq)
        owner = MagicMock()
        owner.set_ip_forwarding.return_value = True
        owner.restore_ip_forwarding.return_value = True

        with patch.object(Configuration, 'get_interface_manager', return_value=owner), \
                patch('builtins.open', side_effect=AssertionError('direct sysfs write')):
            dnsmasq._setup_routing()
            dnsmasq._cleanup_routing()

        owner.set_ip_forwarding.assert_called_once_with(True)
        owner.restore_ip_forwarding.assert_called_once()

    def test_cleanup_manager_prefers_full_service_cleanup(self):
        from wifite.util.cleanup import CleanupManager

        class Service:
            def __init__(self):
                self.stopped = False
                self.cleaned = False

            def stop(self):
                self.stopped = True

            def cleanup(self):
                self.cleaned = True

        service = Service()
        manager = CleanupManager()

        assert manager.stop_process(service, 'service')
        assert service.cleaned
        assert not service.stopped

    def test_cleanup_manager_restore_delegates_to_owner(self):
        from wifite.config import Configuration
        from wifite.util.cleanup import CleanupManager

        manager = CleanupManager()
        owner = MagicMock()
        owner.restore_interface.return_value = True

        with patch.object(Configuration, 'get_interface_manager', return_value=owner):
            assert manager.restore_interface(IFACE, {'mode': 'monitor'})

        owner.restore_interface.assert_called_once_with(IFACE)

    def test_cleanup_manager_refuses_blind_restore_without_owner_state(self):
        from wifite.config import Configuration
        from wifite.util.cleanup import CleanupManager

        manager = CleanupManager()
        owner = MagicMock()
        owner.restore_interface.return_value = False
        owner.is_managed.return_value = False

        with patch.object(Configuration, 'get_interface_manager', return_value=owner):
            assert not manager.restore_interface(IFACE, {'mode': 'monitor'})

        assert manager.cleanup_errors

    def test_cleanup_manager_forwarding_uses_owner(self):
        from wifite.config import Configuration
        from wifite.util.cleanup import CleanupManager

        manager = CleanupManager()
        owner = MagicMock()
        owner.restore_ip_forwarding.return_value = True

        with patch.object(Configuration, 'get_interface_manager', return_value=owner), \
                patch('builtins.open', side_effect=AssertionError('direct sysfs write')):
            assert manager.disable_ip_forwarding()

        owner.restore_ip_forwarding.assert_called_once()
