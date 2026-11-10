import math
import threading

import pytest


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeInterfaces:
    def __init__(self, phys):
        self.phys = phys

    def _get_interface_phy(self, interface):
        return self.phys[interface]


def make_supervisor(clock=None, phys=None):
    from wifite.util.supervisor import RadioProcessSupervisor

    kwargs = {
        'interface_manager': FakeInterfaces(phys or {}),
        'poll_interval': 0.01,
    }
    if clock is not None:
        kwargs['clock'] = clock
    return RadioProcessSupervisor(**kwargs)


def test_zero_deadline_is_unlimited():
    from wifite.util.supervisor import TargetDeadline

    deadline = TargetDeadline(0, clock=FakeClock())
    assert math.isinf(deadline.remaining())
    assert not deadline.expired()
    deadline.check()


def test_deadline_uses_monotonic_clock():
    from wifite.util.supervisor import TargetDeadline, TargetTimeoutExpired

    clock = FakeClock()
    deadline = TargetDeadline(10, clock=clock)
    clock.advance(4)
    assert deadline.remaining() == 6
    clock.advance(6)
    assert deadline.expired()
    with pytest.raises(TargetTimeoutExpired):
        deadline.check()


def test_sleep_is_interruptible():
    from wifite.util.supervisor import TargetScopeCancelled

    clock = FakeClock()
    supervisor = make_supervisor(clock)
    scope = supervisor.target_scope(object(), 30)
    started = threading.Event()

    def sleep_scope():
        started.set()
        try:
            scope.sleep(30)
        except TargetScopeCancelled:
            pass

    worker = threading.Thread(target=sleep_scope)
    worker.start()
    assert started.wait(1)
    scope.close()
    worker.join(1)

    assert not worker.is_alive()


def test_expired_scope_check_raises():
    from wifite.util.supervisor import TargetTimeoutExpired

    clock = FakeClock()
    supervisor = make_supervisor(clock)
    scope = supervisor.target_scope(object(), 5)
    clock.advance(6)
    with pytest.raises(TargetTimeoutExpired):
        scope.check()


def run_acquire(supervisor, scope, interface, started, acquired, errors):
    try:
        started.set()
        with supervisor.radio(interface, 'test', scope):
            acquired.set()
    except Exception as exc:
        errors.append(exc)


def test_same_phy_serializes():
    supervisor = make_supervisor(phys={'wlan0': 'phy0', 'wlan1': 'phy0'})
    first = supervisor.target_scope(object(), 0)
    second = supervisor.target_scope(object(), 0)
    started = threading.Event()
    acquired = threading.Event()
    errors = []

    with supervisor.radio('wlan0', 'capture', first):
        worker = threading.Thread(
            target=run_acquire,
            args=(supervisor, second, 'wlan1', started, acquired, errors),
        )
        worker.start()
        assert started.wait(1)
        assert not acquired.wait(0.1)

    worker.join(1)
    assert acquired.is_set()
    assert errors == []


def test_distinct_phys_run_in_parallel():
    supervisor = make_supervisor(phys={'wlan0': 'phy0', 'wlan1': 'phy1'})
    first = supervisor.target_scope(object(), 0)
    second = supervisor.target_scope(object(), 0)
    started = threading.Event()
    acquired = threading.Event()
    errors = []

    with supervisor.radio('wlan0', 'capture', first):
        worker = threading.Thread(
            target=run_acquire,
            args=(supervisor, second, 'wlan1', started, acquired, errors),
        )
        worker.start()
        assert acquired.wait(1)

    worker.join(1)
    assert errors == []


def test_unknown_phys_do_not_share_lock():
    supervisor = make_supervisor(phys={'wlan0': 'unknown', 'wlan1': 'unknown'})
    first = supervisor.target_scope(object(), 0)
    second = supervisor.target_scope(object(), 0)
    started = threading.Event()
    acquired = threading.Event()
    errors = []

    with supervisor.radio('wlan0', 'capture', first):
        worker = threading.Thread(
            target=run_acquire,
            args=(supervisor, second, 'wlan1', started, acquired, errors),
        )
        worker.start()
        assert acquired.wait(1)

    worker.join(1)
    assert errors == []


def test_lease_releases_after_exception():
    supervisor = make_supervisor(phys={'wlan0': 'phy0'})
    first = supervisor.target_scope(object(), 0)
    second = supervisor.target_scope(object(), 0)

    with pytest.raises(RuntimeError, match='operation failed'):
        with supervisor.radio('wlan0', 'capture', first):
            raise RuntimeError('operation failed')

    with supervisor.radio('wlan0', 'validation', second):
        pass


def test_lease_wait_respects_deadline():
    from wifite.util.supervisor import TargetTimeoutExpired

    clock = FakeClock()
    supervisor = make_supervisor(clock=clock, phys={'wlan0': 'phy0'})
    first = supervisor.target_scope(object(), 0)
    second = supervisor.target_scope(object(), 5)
    started = threading.Event()
    acquired = threading.Event()
    errors = []

    with supervisor.radio('wlan0', 'capture', first):
        worker = threading.Thread(
            target=run_acquire,
            args=(supervisor, second, 'wlan0', started, acquired, errors),
        )
        worker.start()
        assert started.wait(1)
        clock.advance(6)
        worker.join(1)

    assert not worker.is_alive()
    assert not acquired.is_set()
    assert len(errors) == 1
    assert isinstance(errors[0], TargetTimeoutExpired)
