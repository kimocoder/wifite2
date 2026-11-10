import os
import threading
import time

import pytest

from wifite.util.process import Process, ProcessManager


class FakeInterfaces:
    def _get_interface_phy(self, interface):
        return 'unknown'


def make_supervisor():
    from wifite.util.supervisor import RadioProcessSupervisor

    return RadioProcessSupervisor(interface_manager=FakeInterfaces())


def stop_process(process):
    if process is None:
        return
    process.force_kill()
    process.cleanup()


def process_alive(pid):
    try:
        with open(f'/proc/{pid}/stat') as handle:
            state = handle.read().rsplit(') ', 1)[1].split()[0]
        return state != 'Z'
    except (OSError, IndexError):
        return False


def wait_for_exit(pid, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return True
        time.sleep(0.02)
    return not process_alive(pid)


def test_scope_cleanup_spares_other_scope():
    supervisor = make_supervisor()
    first = supervisor.target_scope(object(), 0)
    second = supervisor.target_scope(object(), 0)
    first_process = second_process = None
    try:
        first_process = first.spawn(['sleep', '30'], role='first')
        second_process = second.spawn(['sleep', '30'], role='second')
        first.close()

        assert not first_process.is_running()
        assert second_process.is_running()
    finally:
        first.close()
        second.close()
        stop_process(first_process)
        stop_process(second_process)


def test_scope_cleanup_spares_unscoped_process():
    supervisor = make_supervisor()
    scope = supervisor.target_scope(object(), 0)
    scoped = unscoped = None
    try:
        scoped = scope.spawn(['sleep', '30'], role='capture')
        unscoped = Process(['sleep', '30'], devnull=True)
        scope.close()

        assert not scoped.is_running()
        assert unscoped.is_running()
    finally:
        scope.close()
        stop_process(scoped)
        stop_process(unscoped)


def test_process_identity_mismatch_prevents_signal(monkeypatch):
    supervisor = make_supervisor()
    scope = supervisor.target_scope(object(), 0)
    process = None
    try:
        process = scope.spawn(['sleep', '30'], role='capture')
        process._start_identity = 'different-process'
        killed = []
        monkeypatch.setattr(os, 'killpg', lambda *args: killed.append(args))
        monkeypatch.setattr(os, 'kill', lambda *args: killed.append(args))

        ProcessManager().cleanup_scope(scope.scope_id)

        assert process.is_running()
        assert killed == []
    finally:
        scope.close()
        stop_process(process)


def test_owned_group_cleans_descendant():
    supervisor = make_supervisor()
    scope = supervisor.target_scope(object(), 0)
    process = None
    try:
        process = scope.spawn(
            ['/bin/sh', '-c', 'sleep 30 & echo $!; wait'],
            role='service',
        )
        descendant = int(process.stdoutln().strip())
        assert process_alive(descendant)

        scope.close()

        assert wait_for_exit(descendant)
    finally:
        scope.close()
        stop_process(process)


def test_owned_group_cleans_descendant_after_leader_exits():
    supervisor = make_supervisor()
    scope = supervisor.target_scope(object(), 0)
    process = None
    try:
        process = scope.spawn(
            ['/bin/sh', '-c', 'sleep 30 & echo $!; exit 0'],
            role='service',
        )
        descendant = int(process.stdoutln().strip())
        process.pid.wait(timeout=5)
        assert not process.is_running()
        assert process_alive(descendant)

        scope.close()

        assert wait_for_exit(descendant)
    finally:
        scope.close()
        stop_process(process)


def test_process_limit_does_not_kill_active(monkeypatch):
    from wifite.util.supervisor import ProcessLimitError

    supervisor = make_supervisor()
    scope = supervisor.target_scope(object(), 0)
    process = None
    try:
        process = scope.spawn(['sleep', '30'], role='active')
        monkeypatch.setattr(ProcessManager, 'MAX_PROCESSES', 1)

        with pytest.raises(ProcessLimitError):
            scope.spawn(['sleep', '30'], role='overflow')

        assert process.is_running()
        assert ProcessManager().processes(scope.scope_id) == [process]
    finally:
        scope.close()
        stop_process(process)


def assert_routine_cleanup_preserves_active_process(cleanup):
    supervisor = make_supervisor()
    scope = supervisor.target_scope(object(), 0)
    process = None
    try:
        process = scope.spawn(['sleep', '30'], role='active')
        cleanup()

        assert process.is_running()
        assert process in ProcessManager().processes(scope.scope_id)
    finally:
        scope.close()
        stop_process(process)


def test_memory_cleanup_preserves_active_process():
    from wifite.util.memory import MemoryMonitor

    assert_routine_cleanup_preserves_active_process(MemoryMonitor._standard_cleanup)


def test_fd_cleanup_preserves_active_process():
    from wifite.util.memory import MemoryMonitor

    assert_routine_cleanup_preserves_active_process(MemoryMonitor._fd_cleanup)


def test_configuration_memory_cleanup_preserves_active_process():
    from wifite.config import Configuration

    assert_routine_cleanup_preserves_active_process(Configuration.cleanup_memory)
