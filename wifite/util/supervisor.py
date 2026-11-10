import math
import os
import threading
import time
import uuid
from contextlib import contextmanager


class TargetTimeoutExpired(TimeoutError):
    pass


class TargetScopeCancelled(RuntimeError):
    pass


class RadioLeaseError(RuntimeError):
    pass


class ProcessLimitError(RuntimeError):
    pass


class ServiceHealthError(RuntimeError):
    pass


class TargetDeadline:
    def __init__(self, timeout_seconds, clock=time.monotonic):
        if timeout_seconds is not None and timeout_seconds < 0:
            raise ValueError('Target timeout cannot be negative')
        self.timeout_seconds = timeout_seconds
        self.clock = clock
        self.started_at = clock()

    def remaining(self):
        if not self.timeout_seconds:
            return math.inf
        return max(0.0, self.timeout_seconds - (self.clock() - self.started_at))

    def expired(self):
        return self.remaining() == 0

    def check(self):
        if self.expired():
            raise TargetTimeoutExpired(
                f'Target exceeded its {self.timeout_seconds:g}-second time budget'
            )

    def sleep(self, seconds, cancel_event=None):
        duration = min(max(0.0, seconds), self.remaining())
        if cancel_event is None:
            if duration:
                time.sleep(duration)
        elif cancel_event.wait(duration):
            raise TargetScopeCancelled('Target scope was cancelled')
        self.check()


class TargetScope:
    def __init__(self, supervisor, target, timeout_seconds):
        self.supervisor = supervisor
        self.target = target
        self.scope_id = uuid.uuid4().hex
        self.deadline = TargetDeadline(timeout_seconds, clock=supervisor.clock)
        self.cancel_event = threading.Event()
        self._state_lock = threading.RLock()
        self._closed = False
        self._health_checks = []
        self._log_handles = []
        self._logs_by_path = {}

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _open_log(self, path):
        with self._state_lock:
            if path in self._logs_by_path:
                return self._logs_by_path[path]
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            handle = os.fdopen(fd, 'ab', buffering=0)
            self._log_handles.append(handle)
            self._logs_by_path[path] = handle
            return handle

    def create_log(self, service_name):
        import re
        from ..config import Configuration
        safe_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', service_name).strip('._')
        if not safe_name:
            raise ValueError('Service log name cannot be empty')
        path = Configuration.temp(f'{safe_name}_{self.scope_id}.log')
        self._open_log(path)
        return path

    def spawn(self, command, role, log_path=None):
        self.check()
        from .process import Process
        output = self._open_log(log_path) if log_path is not None else None
        kwargs = {
            'scope_id': self.scope_id,
            'role': role,
            'owned_group': True,
        }
        if output is not None:
            kwargs['stdout'] = output
            kwargs['stderr'] = output
        return Process(command, **kwargs)

    def register_health(self, name, callback, required=True):
        with self._state_lock:
            self._health_checks.append((name, callback, required))

    def clear_health(self):
        with self._state_lock:
            self._health_checks.clear()

    def unregister_health(self, name):
        with self._state_lock:
            self._health_checks = [
                check for check in self._health_checks if check[0] != name
            ]

    def remaining(self):
        return self.deadline.remaining()

    def sleep(self, seconds):
        self.deadline.sleep(seconds, self.cancel_event)

    def check(self):
        if self.cancel_event.is_set() and not self._closed:
            raise TargetScopeCancelled('Target scope was cancelled')
        self.deadline.check()
        with self._state_lock:
            checks = list(self._health_checks)
        for name, callback, required in checks:
            try:
                healthy = callback()
            except Exception as exc:
                raise ServiceHealthError(f'Service health check failed: {name}') from exc
            if required and not healthy:
                raise ServiceHealthError(f'Required service is not running: {name}')

    def cancel(self):
        self.cancel_event.set()

    def close(self):
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self.cancel_event.set()
        from .process import ProcessManager
        ProcessManager().cleanup_scope(self.scope_id)
        with self._state_lock:
            handles = list(self._log_handles)
            self._log_handles.clear()
            self._logs_by_path.clear()
        for handle in handles:
            try:
                handle.close()
            except OSError:
                pass
        self.supervisor._close_scope(self)


class RadioProcessSupervisor:
    def __init__(self, interface_manager=None, clock=time.monotonic, poll_interval=0.05):
        self.interface_manager = interface_manager
        self.clock = clock
        self.poll_interval = poll_interval
        self._lock_table_guard = threading.Lock()
        self._interface_locks = {}
        self._phy_locks = {}
        self._scopes = set()
        self._scopes_lock = threading.Lock()

    def target_scope(self, target, timeout_seconds):
        scope = TargetScope(self, target, timeout_seconds)
        with self._scopes_lock:
            self._scopes.add(scope)
        return scope

    def _get_interface_manager(self):
        if self.interface_manager is None:
            from ..config import Configuration
            self.interface_manager = Configuration.get_interface_manager()
        return self.interface_manager

    def _lock_for(self, table, key):
        with self._lock_table_guard:
            if key not in table:
                table[key] = threading.RLock()
            return table[key]

    def _acquire(self, lock, scope):
        while True:
            scope.check()
            wait = min(self.poll_interval, scope.remaining())
            if lock.acquire(timeout=wait):
                return

    @contextmanager
    def radio(self, interface, role, scope):
        del role
        phy = self._get_interface_manager()._get_interface_phy(interface)
        interface_lock = self._lock_for(self._interface_locks, interface)
        phy_lock = None
        if phy and phy != 'unknown':
            phy_lock = self._lock_for(self._phy_locks, phy)

        interface_acquired = False
        phy_acquired = False
        try:
            self._acquire(interface_lock, scope)
            interface_acquired = True
            if phy_lock is not None:
                self._acquire(phy_lock, scope)
                phy_acquired = True
            yield
        finally:
            if phy_acquired:
                phy_lock.release()
            if interface_acquired:
                interface_lock.release()

    def _close_scope(self, scope):
        with self._scopes_lock:
            self._scopes.discard(scope)

    def close(self):
        with self._scopes_lock:
            scopes = list(self._scopes)
        for scope in scopes:
            scope.close()
