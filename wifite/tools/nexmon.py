#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Optional Broadcom FullMAC / Nexmon support.

Nexmon is a community patched ``brcmfmac`` firmware shipped with the
``nexutil`` userspace tool.  This module never installs firmware, replaces
drivers, or assumes that every Broadcom adapter is patched: every capability
decision comes from the firmware's own capability mask, read with bounded
read-only ``nexutil`` calls (base64 output first, hexdump fallback for
nexutil builds without ``-R``; the firmware string comes from ``nexutil``
revinfo, not the kernel driver version).

Detection is fail-closed.  A missing tool, a nonzero exit status, a timeout,
malformed base64, a payload that is not exactly four bytes, an unknown driver,
or an unreadable safety-critical state all result in "no Nexmon capability"
and injection stays disabled.

Monitor setup is guarded: it refuses to touch an interface that is
associated, carries a default route, is managed by NetworkManager, is in an
AP/P2P/mesh/adhoc mode, or shares a PHY with such an interface.  The firmware
advertises injection but this module makes no claim that injection has been
verified over the air.

Sessions are tracked in process memory only.  If a wifite process is killed,
its monitor survives; the next ``start_monitor`` call detects that leaked
monitor (``{station}mon`` in monitor mode on the same PHY with the station
down and no live session) and removes it so the preferred name is reused.  A
monitor the user configured while the station is up is left untouched.
"""

import base64
import binascii
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..config.validators import validate_interface_name
from ..util.logger import log_debug, log_error, log_info, log_warning
from ..util.process import Process
from .dependency import Dependency

# Capability bits advertised by patched firmware (nexmon
# patches/include/capabilities.h).  Do not extend these meanings.
CAPABILITY_MONITOR = 0x1
CAPABILITY_RADIOTAP = 0x2
CAPABILITY_INJECTION = 0x4

# nexutil custom command used to read the capability mask.
CAPABILITY_COMMAND = 400
CAPABILITY_LENGTH = 4

# nexutil prints data bytes as "%02x " in 16 fixed columns followed by an
# ASCII column (utilities/nexutil/nexutil.c, hexdump()).
_HEXDUMP_LINE_RE = re.compile(r'^0x[0-9a-fA-F]+:')
_HEXDUMP_COLS = 16

# Radiotap monitor mode requested from the firmware after interface creation.
RADIOTAP_MONITOR_MODE = 2

_SUPPORTED_DRIVER = 'brcmfmac'
_NEXUTIL = 'nexutil'
_NEXUTIL_TIMEOUT = 5
_CMD_TIMEOUT = 5
_NM_TIMEOUT = 8

_CACHE_TTL = 15.0
_CACHE_MAX_ENTRIES = 32

_AP_P2P_MESH_MODES = frozenset({'AP', 'p2p', 'mesh', 'adhoc'})
_MAX_INTERFACE_NAME = 15

_cache: Dict[str, Tuple[float, Optional['NexmonCapabilities']]] = {}
_cache_lock = threading.Lock()

_sessions: Dict[str, 'NexmonSession'] = {}
_sessions_lock = threading.Lock()


class NexmonError(Exception):
    """Base error for Nexmon probing and lifecycle operations."""


class NexmonUnavailable(NexmonError):
    """The interface is not a usable Nexmon/brcmfmac device."""


class NexmonRefused(NexmonError):
    """Taking over the interface would be unsafe."""


@dataclass(frozen=True)
class NexmonCapabilities:
    """Capabilities advertised by patched brcmfmac firmware."""

    interface: str
    driver: str
    mask: int
    firmware: Optional[str] = None

    @property
    def monitor(self) -> bool:
        return bool(self.mask & CAPABILITY_MONITOR)

    @property
    def radiotap(self) -> bool:
        return bool(self.mask & CAPABILITY_RADIOTAP)

    @property
    def injection(self) -> bool:
        return bool(self.mask & CAPABILITY_INJECTION)

    @property
    def native_monitor_ready(self) -> bool:
        """A native monitor interface needs both monitor and radiotap."""
        return self.monitor and self.radiotap

    def describe(self) -> str:
        bits = [
            'monitor' if self.monitor else 'no-monitor',
            'radiotap' if self.radiotap else 'no-radiotap',
            'injection' if self.injection else 'no-injection',
        ]
        version = self.firmware or 'unknown firmware'
        return f'{version} ({", ".join(bits)})'


@dataclass
class NexmonSession:
    """State captured for a monitor interface that wifite created."""

    station: str
    monitor: str
    phy: str
    monitor_ifindex: Optional[int]
    station_was_up: bool
    power_save_was_enabled: Optional[bool]
    owned: bool = True
    active: bool = True


# ---------------------------------------------------------------------------
# Low-level command and sysfs helpers
# ---------------------------------------------------------------------------


def _run(cmd: List[str], timeout: int = _CMD_TIMEOUT):
    """Run a bounded command list; return CompletedProcess or None."""
    try:
        return Process.run_simple(cmd, timeout=timeout)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ValueError):
        return None


def _run_ok(cmd: List[str], timeout: int = _CMD_TIMEOUT) -> bool:
    result = _run(cmd, timeout=timeout)
    return result is not None and result.returncode == 0


def _require_ok(cmd: List[str], message: str, timeout: int = _CMD_TIMEOUT) -> None:
    if not _run_ok(cmd, timeout=timeout):
        raise NexmonError(message)


def _read_sysfs(path: str) -> Optional[str]:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return handle.read().strip()
    except OSError:
        return None


def _ifindex(interface: str) -> Optional[int]:
    value = _read_sysfs(f'/sys/class/net/{interface}/ifindex')
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _is_up(interface: str) -> Optional[bool]:
    flags = _read_sysfs(f'/sys/class/net/{interface}/flags')
    if flags is None:
        return None
    try:
        return bool(int(flags, 16) & 0x1)
    except ValueError:
        return None


def _read_phy(interface: str) -> Optional[str]:
    link = f'/sys/class/net/{interface}/phy80211'
    try:
        target = os.path.basename(os.readlink(link))
        if target.startswith('phy'):
            return target
    except OSError:
        pass
    result = _run(['iw', 'dev', interface, 'info'])
    if result is not None and result.returncode == 0:
        match = re.search(r'wiphy\s+(\d+)', result.stdout or '')
        if match:
            return f'phy{match.group(1)}'
    return None


def _read_driver(interface: str) -> str:
    links = [f'/sys/class/net/{interface}/device/driver']
    phy = _read_phy(interface)
    if phy:
        links.append(f'/sys/class/ieee80211/{phy}/device/driver')
    for link in links:
        try:
            name = os.path.basename(os.readlink(link))
            if name:
                return name
        except OSError:
            continue
    try:
        from ..util.interface_manager import InterfaceManager

        name = InterfaceManager._get_interface_driver(interface)
        if name and name != 'unknown':
            return name
    except Exception:
        pass
    return 'unknown'


def _firmware_version(interface: str) -> Optional[str]:
    """Firmware version reported by the chip via ``nexutil`` revinfo.

    This is the real firmware build string (e.g. ``7.45.265 ... nexmon.org
    ...``), not the kernel driver version exposed under ``/sys/module``.
    """
    result = _run([_NEXUTIL, '-I', interface, '-V'], timeout=_NEXUTIL_TIMEOUT)
    if result is None or result.returncode != 0:
        return None
    match = re.search(r'^firmware\s+(\S.*?)\s*$',
                      result.stdout or '', re.MULTILINE)
    return match.group(1) if match else None


def _interface_mode(interface: str) -> Optional[str]:
    result = _run(['iw', 'dev', interface, 'info'])
    if result is None or result.returncode != 0:
        return None
    match = re.search(r'^\s*type\s+(.+?)\s*$', result.stdout or '', re.MULTILINE)
    if not match:
        return None
    mode = match.group(1).strip().lower()
    if mode == 'mesh point':
        return 'mesh'
    if mode == 'ibss':
        return 'adhoc'
    if mode.startswith('p2p'):
        return 'p2p'
    if mode == 'ap':
        return 'AP'
    if mode in ('managed', 'monitor'):
        return mode
    return mode or None


def _is_associated(interface: str) -> Optional[bool]:
    result = _run(['iw', 'dev', interface, 'link'])
    if result is None or result.returncode != 0:
        return None
    text = (result.stdout or '').lower()
    if 'not connected' in text:
        return False
    if 'connected to' in text:
        return True
    return None


def _default_route_devices() -> Optional[set]:
    devices = set()
    for cmd in (
        ['ip', 'route', 'show', 'default'],
        ['ip', '-6', 'route', 'show', 'default'],
    ):
        result = _run(cmd)
        if result is None or result.returncode != 0:
            return None
        for line in (result.stdout or '').splitlines():
            match = re.search(r'\bdev\s+(\S+)', line)
            if match:
                devices.add(match.group(1))
    return devices


def _nm_device_state(interface: str) -> Optional[str]:
    """Return 'absent', 'unmanaged', or another NetworkManager state."""
    if not Process.exists('nmcli'):
        return 'absent'
    result = _run(['nmcli', '-t', '-f', 'DEVICE,STATE', 'device', 'status'],
                  timeout=_NM_TIMEOUT)
    if result is None:
        return None
    if result.returncode != 0:
        text = f'{result.stdout or ""}\n{result.stderr or ""}'.lower()
        if 'not running' in text:
            return 'absent'
        return None
    for line in (result.stdout or '').splitlines():
        parts = line.split(':')
        if len(parts) >= 2 and parts[0] == interface:
            return parts[1].strip().lower()
    return 'absent'


def _power_save_state(interface: str) -> Optional[bool]:
    result = _run(['iw', 'dev', interface, 'get', 'power_save'])
    if result is None or result.returncode != 0:
        return None
    match = re.search(r'power save:\s*(on|off)', result.stdout or '', re.IGNORECASE)
    if not match:
        return None
    return match.group(1).lower() == 'on'


def _set_power_save(interface: str, enabled: bool) -> bool:
    value = 'on' if enabled else 'off'
    return _run_ok(['iw', 'dev', interface, 'set', 'power_save', value])


def _radiotap_monitor_mode(interface: str) -> Optional[int]:
    result = _run([_NEXUTIL, '-I', interface, '-m'], timeout=_NEXUTIL_TIMEOUT)
    if result is None or result.returncode != 0:
        return None
    match = re.search(r'monitor:\s*(-?\d+)', result.stdout or '')
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    match = re.search(r'-?\d+', result.stdout or '')
    if match:
        try:
            return int(match.group(0))
        except ValueError:
            return None
    return None


def _delete_interface(interface: str) -> bool:
    if _ifindex(interface) is None:
        return True
    return _run_ok(['iw', 'dev', interface, 'del'])


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------


def _decode_base64_mask(payload: str) -> Optional[int]:
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != CAPABILITY_LENGTH:
        return None
    return int.from_bytes(raw, 'little')


def _parse_hexdump(text: str) -> Optional[bytes]:
    """Parse the fixed-column hexdump nexutil prints without ``-R``.

    Every nexutil generation (upstream and forks) shares this format: data
    bytes as ``%02x `` in 16 fixed columns, then an ASCII column.  Only the
    byte columns are read, so letters in the ASCII column cannot be mistaken
    for data.
    """
    data = bytearray()
    for line in text.splitlines():
        match = _HEXDUMP_LINE_RE.match(line)
        if match is None:
            continue
        fields = line[match.end():match.end() + 1 + 3 * _HEXDUMP_COLS][1:]
        for i in range(_HEXDUMP_COLS):
            field = fields[i * 3:i * 3 + 3]
            if len(field) < 2 or not field[0:2].strip():
                break
            try:
                data.append(int(field[0:2], 16))
            except ValueError:
                break
    return bytes(data) if data else None


def _query_capability_mask(interface: str) -> Optional[int]:
    """Read the firmware capability mask, or None on any ambiguity.

    Prefers the base64 payload printed by ``nexutil -R``.  Builds without
    ``-R`` (older upstream nexutil) reject the option or print a hexdump
    instead, so the mask is re-read without ``-R`` and parsed from the
    hexdump columns.  Anything undecodable fails closed.
    """
    base_cmd = [
        _NEXUTIL,
        '-I',
        interface,
        '-g',
        str(CAPABILITY_COMMAND),
        '-l',
        str(CAPABILITY_LENGTH),
    ]

    result = _run(base_cmd + ['-R'], timeout=_NEXUTIL_TIMEOUT)
    if result is None:
        return None
    if result.returncode == 0:
        mask = _decode_base64_mask((result.stdout or '').strip())
        if mask is not None:
            return mask

    result = _run(base_cmd, timeout=_NEXUTIL_TIMEOUT)
    if result is None or result.returncode != 0:
        return None
    raw = _parse_hexdump(result.stdout or '')
    if raw is None or len(raw) != CAPABILITY_LENGTH:
        return None
    return int.from_bytes(raw, 'little')


def _probe_uncached(interface: str) -> Optional[NexmonCapabilities]:
    driver = _read_driver(interface)
    if driver != _SUPPORTED_DRIVER:
        return None
    mask = _query_capability_mask(interface)
    if mask is None or mask == 0:
        return None
    return NexmonCapabilities(
        interface=interface,
        driver=driver,
        mask=mask,
        firmware=_firmware_version(interface),
    )


def probe(interface: str, use_cache: bool = True) -> Optional[NexmonCapabilities]:
    """Return advertised Nexmon capabilities, or None.

    This performs at most three bounded read-only ``nexutil`` calls
    (capability mask via base64 or hexdump fallback, plus firmware
    revinfo) and never changes radio state.  Negative results are cached
    briefly as well so a system with ``nexutil`` installed but stock
    firmware is not re-probed for every capability query.
    """
    try:
        validate_interface_name(interface)
    except ValueError:
        return None

    key = f'{interface}:{_ifindex(interface)}'
    now = time.monotonic()
    if use_cache:
        with _cache_lock:
            entry = _cache.get(key)
        if entry is not None and now - entry[0] < _CACHE_TTL:
            return entry[1]

    capabilities = _probe_uncached(interface)

    with _cache_lock:
        if len(_cache) >= _CACHE_MAX_ENTRIES:
            for stale_key in [
                k for k, (stamp, _) in _cache.items() if now - stamp >= _CACHE_TTL
            ]:
                _cache.pop(stale_key, None)
            while len(_cache) >= _CACHE_MAX_ENTRIES:
                _cache.pop(next(iter(_cache)))
        _cache[key] = (now, capabilities)
    return capabilities


def invalidate_cache(interface: Optional[str] = None) -> None:
    with _cache_lock:
        if interface is None:
            _cache.clear()
        else:
            for key in [k for k in _cache if k.split(':', 1)[0] == interface]:
                _cache.pop(key, None)


def reset_cache() -> None:
    invalidate_cache(None)


def is_nexmon_interface(interface: str) -> bool:
    return probe(interface) is not None


def system_applicable() -> bool:
    """True when any netdev is driven by brcmfmac (cheap sysfs scan)."""
    try:
        names = os.listdir('/sys/class/net')
    except OSError:
        return False
    for name in names:
        try:
            driver = os.path.basename(
                os.readlink(f'/sys/class/net/{name}/device/driver')
            )
        except OSError:
            continue
        if driver == _SUPPORTED_DRIVER:
            return True
    return False


# ---------------------------------------------------------------------------
# Guarded monitor lifecycle
# ---------------------------------------------------------------------------


def _assert_safe_to_take_over(station: str, phy: str) -> None:
    routes = _default_route_devices()
    if routes is None:
        raise NexmonRefused('could not read the system routing table')
    if station in routes:
        raise NexmonRefused(f'{station} carries a default route')

    if _is_associated(station) is not False:
        raise NexmonRefused(f'{station} is associated or its link state is unknown')

    nm_state = _nm_device_state(station)
    if nm_state is None:
        raise NexmonRefused('could not determine NetworkManager state')
    if nm_state not in ('absent', 'unmanaged'):
        raise NexmonRefused(
            f'{station} is managed by NetworkManager ({nm_state}); '
            'mark it unmanaged before using Nexmon monitor mode'
        )

    try:
        from .iw import Iw

        siblings = Iw.get_interfaces()
    except Exception as exc:
        raise NexmonRefused(f'could not enumerate wireless interfaces: {exc}') from exc

    for sibling in siblings:
        if sibling == station:
            continue
        if _read_phy(sibling) != phy:
            continue
        mode = _interface_mode(sibling)
        if mode is None:
            raise NexmonRefused(f'could not determine the mode of {sibling} on {phy}')
        if mode in _AP_P2P_MESH_MODES:
            raise NexmonRefused(f'{sibling} is using {mode} mode on {phy}')
        if mode == 'managed' and _is_associated(sibling) is not False:
            raise NexmonRefused(f'{sibling} is associated on {phy}')
        if sibling in routes:
            raise NexmonRefused(f'{sibling} carries a default route')


def _sweep_leaked_monitor(station: str, phy: str) -> Optional[str]:
    """Remove a monitor leaked by a previously killed wifite process.

    While a Nexmon session is active the station netdev is held down, so a
    ``{station}mon`` interface in monitor mode on ``phy`` with the station
    down and no registered session is the fingerprint of a lifecycle whose
    owning process died.  Freeing the name lets the next run reuse it; the
    station's original power-save state cannot be recovered and is left
    as-is.  A monitor the user configured while the station is up, or one
    owned by a live session, is left untouched.
    """
    name = f'{station}mon'
    if len(name.encode('utf-8')) > _MAX_INTERFACE_NAME:
        return None
    if _lookup_session(name) is not None:
        return None
    if _ifindex(name) is None:
        return None
    if _read_phy(name) != phy:
        return None
    if _interface_mode(name) != 'monitor':
        return None
    if _is_up(station) is not False:
        return None
    if not _delete_interface(name):
        return None
    return name


def _select_monitor_name(station: str) -> str:
    candidates = [f'{station}mon'] + [f'mon{i}' for i in range(10)]
    for name in candidates:
        if len(name.encode('utf-8')) > _MAX_INTERFACE_NAME:
            continue
        if _ifindex(name) is None:
            return name
    raise NexmonRefused('no unused monitor interface name is available')


def _create_monitor(station: str, phy: str, monitor: str) -> None:
    result = _run(['iw', 'phy', phy, 'interface', 'add', monitor, 'type', 'monitor'])
    if result is None or result.returncode != 0:
        # Older iw builds accept the station-centric form.
        _run(['iw', 'dev', station, 'interface', 'add', monitor, 'type', 'monitor'])
    if _ifindex(monitor) is None:
        raise NexmonError(f'failed to create monitor interface {monitor}')


def _restore_session(session: NexmonSession) -> List[str]:
    errors: List[str] = []

    if session.monitor:
        current_ifindex = _ifindex(session.monitor)
        if current_ifindex is not None:
            if (
                session.monitor_ifindex is not None
                and current_ifindex != session.monitor_ifindex
            ):
                errors.append(
                    f'{session.monitor} changed identity '
                    f'(ifindex {session.monitor_ifindex} -> {current_ifindex}); '
                    'refusing to delete it'
                )
            elif not _delete_interface(session.monitor):
                errors.append(f'failed to delete monitor interface {session.monitor}')

    if session.station_was_up:
        if _is_up(session.station) is False:
            if not _run_ok(['ip', 'link', 'set', session.station, 'up']):
                errors.append(f'failed to bring {session.station} back up')
    elif _is_up(session.station) is True:
        if not _run_ok(['ip', 'link', 'set', session.station, 'down']):
            errors.append(f'failed to bring {session.station} back down')

    if session.power_save_was_enabled is not None:
        if not _set_power_save(session.station, session.power_save_was_enabled):
            errors.append(
                f'failed to restore power saving on {session.station}'
            )

    return errors


def _register_session(session: NexmonSession) -> None:
    with _sessions_lock:
        _sessions[session.station] = session


def _lookup_session(interface: str) -> Optional[NexmonSession]:
    with _sessions_lock:
        for session in _sessions.values():
            if interface in (session.station, session.monitor):
                return session
    return None


def has_session(interface: str) -> bool:
    return _lookup_session(interface) is not None


def start_monitor(interface: str) -> str:
    """Create (or reuse) a Nexmon monitor interface for ``interface``.

    Returns the monitor interface name.  Raises NexmonUnavailable when the
    device does not advertise the required capabilities and NexmonRefused when
    taking it over would be unsafe.  On failure only interfaces created by
    this call are removed.
    """
    validate_interface_name(interface)

    existing = _lookup_session(interface)
    if existing is not None and existing.active:
        return existing.monitor

    capabilities = probe(interface)
    if capabilities is None:
        raise NexmonUnavailable(
            f'{interface} does not advertise Nexmon capabilities '
            '(patched brcmfmac firmware and nexutil are required)'
        )
    if not capabilities.native_monitor_ready:
        raise NexmonUnavailable(
            f'{interface} advertises {capabilities.describe()}; '
            'monitor and radiotap support are both required'
        )

    mode = _interface_mode(interface)
    if mode is None:
        raise NexmonRefused(f'could not determine the mode of {interface}')
    if mode == 'monitor':
        log_debug('Nexmon', f'{interface} is already a monitor interface; reusing it')
        return interface
    if mode != 'managed':
        raise NexmonRefused(
            f'{interface} is in {mode} mode; only a managed station can be taken over'
        )

    phy = _read_phy(interface)
    if not phy:
        raise NexmonRefused(f'could not determine the PHY of {interface}')

    _assert_safe_to_take_over(interface, phy)

    leaked = _sweep_leaked_monitor(interface, phy)
    if leaked is not None:
        log_warning('Nexmon',
                    f'Removed monitor interface {leaked} leaked by a previous run')

    monitor = _select_monitor_name(interface)
    station_was_up = _is_up(interface)
    if station_was_up is None:
        raise NexmonRefused(f'could not read the administrative state of {interface}')
    power_save_was_enabled = _power_save_state(interface)

    monitor_ifindex: Optional[int] = None
    session: Optional[NexmonSession] = None
    try:
        if not station_was_up:
            _require_ok(
                ['ip', 'link', 'set', interface, 'up'],
                f'failed to bring {interface} up',
            )

        if _is_associated(interface) is not False:
            raise NexmonRefused(f'{interface} became associated during setup')

        if power_save_was_enabled is not None:
            if not _set_power_save(interface, False):
                log_warning('Nexmon', f'Could not disable power saving on {interface}')

        _create_monitor(interface, phy, monitor)
        monitor_ifindex = _ifindex(monitor)
        if monitor_ifindex is None:
            raise NexmonError(f'{monitor} disappeared after creation')

        _require_ok(['ip', 'link', 'set', monitor, 'up'], f'failed to bring {monitor} up')
        if _interface_mode(monitor) != 'monitor':
            raise NexmonError(f'{monitor} is not in monitor mode after creation')

        radiotap_mode = _radiotap_monitor_mode(monitor)
        if radiotap_mode != RADIOTAP_MONITOR_MODE:
            _require_ok(
                [_NEXUTIL, '-I', monitor, f'-m{RADIOTAP_MONITOR_MODE}'],
                f'firmware refused radiotap monitor mode on {monitor}',
                timeout=_NEXUTIL_TIMEOUT,
            )
            if _radiotap_monitor_mode(monitor) != RADIOTAP_MONITOR_MODE:
                raise NexmonError(
                    f'firmware did not report radiotap monitor mode on {monitor}'
                )

        # cfg80211 can only hop channels while the station netdev is down.
        _require_ok(['ip', 'link', 'set', interface, 'down'],
                    f'failed to bring {interface} down')
        if _is_up(interface) is not False:
            raise NexmonError(f'{interface} is still up; cannot guarantee channel hopping')

        session = NexmonSession(
            station=interface,
            monitor=monitor,
            phy=phy,
            monitor_ifindex=monitor_ifindex,
            station_was_up=station_was_up,
            power_save_was_enabled=power_save_was_enabled,
            owned=True,
            active=True,
        )
        _register_session(session)
        invalidate_cache(interface)
        invalidate_cache(monitor)
        log_info('Nexmon', f'Created monitor interface {monitor} on {interface} ({phy})')
        return monitor

    except BaseException:
        if session is None:
            session = NexmonSession(
                station=interface,
                monitor=monitor,
                phy=phy,
                monitor_ifindex=monitor_ifindex,
                station_was_up=station_was_up,
                power_save_was_enabled=power_save_was_enabled,
                owned=True,
                active=False,
            )
        errors = _restore_session(session)
        if errors:
            # Keep the record so exit cleanup can retry the partial teardown.
            _register_session(session)
            for error in errors:
                log_error('Nexmon', f'Rollback error: {error}')
        invalidate_cache(interface)
        invalidate_cache(monitor)
        raise


def stop(interface: str) -> bool:
    """Remove an owned Nexmon monitor and restore the station.

    ``interface`` may be the monitor or the station name.  Preconfigured
    monitors that wifite does not own are left untouched (returns False).
    Repeated calls after a successful stop are harmless.
    """
    try:
        validate_interface_name(interface)
    except ValueError:
        return False

    session = _lookup_session(interface)
    if session is None:
        return False
    if not session.owned:
        with _sessions_lock:
            _sessions.pop(session.station, None)
        return True

    errors = _restore_session(session)
    invalidate_cache(session.station)
    invalidate_cache(session.monitor)
    if errors:
        for error in errors:
            log_error('Nexmon', f'Cleanup error: {error}')
        return False

    with _sessions_lock:
        current = _sessions.get(session.station)
        if current is session:
            _sessions.pop(session.station, None)
    log_info('Nexmon', f'Removed monitor interface {session.monitor}')
    return True


def cleanup_all() -> List[str]:
    """Tear down every owned Nexmon session.

    Returns the list of station interfaces that were restored.  Sessions whose
    teardown fails are kept so a later call can retry.
    """
    with _sessions_lock:
        sessions = list(_sessions.values())

    restored: List[str] = []
    for session in sessions:
        if not session.owned:
            with _sessions_lock:
                _sessions.pop(session.station, None)
            restored.append(session.station)
            continue

        errors = _restore_session(session)
        invalidate_cache(session.station)
        invalidate_cache(session.monitor)
        if errors:
            for error in errors:
                log_error('Nexmon', f'Cleanup error: {error}')
            continue

        with _sessions_lock:
            current = _sessions.get(session.station)
            if current is session:
                _sessions.pop(session.station, None)
        restored.append(session.station)

    return restored


def self_test(interface: str) -> bool:
    """Live monitor smoke test through the guarded lifecycle."""
    capabilities = probe(interface)
    if capabilities is None:
        return False
    if _interface_mode(interface) == 'monitor':
        return True
    if not capabilities.native_monitor_ready:
        return False
    try:
        monitor = start_monitor(interface)
    except NexmonError as exc:
        log_debug('Nexmon', f'Monitor self-test refused for {interface}: {exc}')
        return False
    try:
        return _interface_mode(monitor) == 'monitor'
    finally:
        stop(interface)


class Nexmon(Dependency):
    """Dependency-check entry point and public facade."""

    dependency_required = False
    dependency_name = _NEXUTIL
    dependency_url = 'https://github.com/seemoo-lab/nexmon'
    dependency_category = Dependency.CATEGORY_NEXMON

    probe = staticmethod(probe)
    is_nexmon_interface = staticmethod(is_nexmon_interface)
    system_applicable = staticmethod(system_applicable)
    start_monitor = staticmethod(start_monitor)
    stop = staticmethod(stop)
    cleanup_all = staticmethod(cleanup_all)
    self_test = staticmethod(self_test)
    has_session = staticmethod(has_session)
    reset_cache = staticmethod(reset_cache)
    invalidate_cache = staticmethod(invalidate_cache)


__all__ = [
    'Nexmon',
    'NexmonCapabilities',
    'NexmonError',
    'NexmonUnavailable',
    'NexmonRefused',
    'NexmonSession',
    'CAPABILITY_MONITOR',
    'CAPABILITY_RADIOTAP',
    'CAPABILITY_INJECTION',
    'probe',
    'is_nexmon_interface',
    'system_applicable',
    'start_monitor',
    'stop',
    'cleanup_all',
    'self_test',
    'has_session',
    'reset_cache',
    'invalidate_cache',
]