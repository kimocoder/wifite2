#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
hcxdumptool Wrapper

This module provides a wrapper around hcxdumptool for capturing WPA3-SAE
handshakes and other wireless frames with PMF awareness.
"""

from .dependency import Dependency
from ..util.process import Process
from ..util.hcxtools import channel_spec, filter_hash_lines
from ..util.color import Color
from ..util.logger import log_warning
from ..config import Configuration

import os
import re
import time
import signal


def _hand_over_monitor_mode(interfaces):
    """Return Wifite-owned monitor interfaces to managed mode.

    hcxdumptool 7+ sets (and restores) monitor mode itself. An interface
    wifite already armed makes hcxdumptool fight over mode and channel,
    which is what upstream warns against. Only hand over interfaces whose
    monitor mode is tracked by Wifite; an untracked monitor device may be
    controlled by a driver-specific mode such as qcacld con_mode.
    """
    handed_over = []
    try:
        version = HcxDumpTool.check_version()
        if not version or int(version.split('.')[0]) < 7:
            return handed_over
        manager = Configuration.get_interface_manager()
    except Exception:
        return handed_over

    for iface in interfaces:
        try:
            # qcacld/ICNSS2 monitor mode is controlled by con_mode. The
            # managed-mode handoff uses iw/ip and can leave wlan0 down on
            # this driver, so let hcxdumptool use the existing monitor netdev.
            from .airmon import Airmon
            iface_info = Airmon.get_iface_info(iface)
            if iface_info and iface_info.driver == 'icnss2':
                continue
            state = manager.get_interface_state(iface)
            if state.get('mode') != 'monitor' or not manager.is_managed(iface):
                continue
            if manager.set_interface_mode(iface, 'managed'):
                handed_over.append(iface)
        except Exception:
            continue
    return handed_over


def _return_monitor_mode(interfaces):
    """Re-arm interfaces after hcxdumptool restored them to managed."""
    if not interfaces:
        return
    try:
        manager = Configuration.get_interface_manager()
    except Exception:
        return
    for iface in interfaces:
        try:
            manager.set_interface_mode(iface, 'monitor')
        except Exception:
            pass


_ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')


def _exit_reason(text):
    """Translate hcxdumptool's own stop lines into one human sentence.

    hcxdumptool reports why it stopped in its closing lines, and it exits 0
    for both a watchdog timeout and a --tot expiry, so the status alone
    cannot tell a dead radio from a finished capture.

    Returns '' for anything unrecognised, including hcxdumptool's real error
    lines, so callers fall back to showing those verbatim. The error count is
    checked before our own SIGTERM line: the SIGTERM is ours, the errors are
    the news.
    """
    if not text:
        return ''
    clean = _ANSI_ESCAPE.sub('', text)
    if re.search(r'exit on watchdog', clean, re.I):
        return 'no packets received (watchdog timeout)'
    if re.search(r'exit on tot\b', clean, re.I):
        return 'capture timer expired'
    match = re.search(r'(\d+) ERROR\(s\) during runtime', clean)
    if match:
        return ('%s runtime error(s); usually a broken driver or a shared '
                'interface' % match.group(1))
    return ''


_RDS_ROW = re.compile(r'^\d+\|')
_BENIGN_EXIT = re.compile(r'exit on (?:sigterm|eapol)$', re.I)
# hcxdumptool prints these on every start. Returning one as the reason says
# nothing about why a capture stopped, so they are skipped, never returned.
_NOISE_LINE = re.compile(
    r'^(?:warning|make sure hcxdumptool|checkout \(and understand\)|'
    r'starting in headless mode|this is a highly experimental|'
    r'it is made to detect|misuse within a network|irreparable damage|'
    r'not understanding what you were doing|\d+ Packet\(s\) (?:captured|dropped)'
    r' by kernel)', re.I)


def _last_meaningful_line(text):
    """Last line of hcxdumptool output that tells a human anything.

    Skips display rows, ANSI-only fragments and blank lines. A trailing
    benign exit line ends the search with '' : the stop was ours (SIGTERM)
    or a success (--exitoneapol), so nothing went wrong and the statistics
    above it are not a failure reason.
    """
    for line in reversed(text.splitlines()):
        clean = _ANSI_ESCAPE.sub('', line).strip()
        if not clean:
            continue
        if _RDS_ROW.match(clean):
            continue
        if _NOISE_LINE.match(clean):
            continue
        if _BENIGN_EXIT.search(clean):
            return ''
        return clean
    return ''


class HcxDumpTool(Dependency):
    """Wrapper around hcxdumptool program for SAE handshake capture."""

    dependency_required = False  # Optional for WPA3 attacks
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, interface=None, channel=None, target_bssid=None,
                 output_file=None, enable_deauth=True, pmf_required=False,
                 manage_interface=False, band=None, active_monitor=None,
                 exitoneapol=None, scope=None):
        """
        Initialize hcxdumptool wrapper.

        Args:
            interface: Wireless interface(s) in monitor mode (string or list)
            channel: Channel to monitor (optional)
            target_bssid: Target BSSID to filter (optional)
            output_file: Output pcapng file path
            enable_deauth: Enable deauth attacks (default: True)
            pmf_required: Target has PMF required (disables deauth)
            manage_interface: Hand a wifite-armed monitor interface back to
                managed mode so hcxdumptool can own the monitor lifecycle.
                Only use when no other tool shares the interface.
            band: '2.4', '5' or '6' to disambiguate the channel number
                (6 GHz reuses 1-233); None keeps the historical heuristic.
            active_monitor: Enable hcxdumptool's active-monitor ACK (-A).
                None uses Configuration.hcxdump_active_monitor (default off).
                Active monitor is broken on many mt76 drivers and can reduce
                capture to zero, so it must never be enabled implicitly.
            exitoneapol: hcxdumptool exit bitmask (2=M1M2M3, 4=M1M2).
                Only used when a target BPF filter can be installed, so
                another AP's pair cannot end the session early.
        """
        Configuration.initialize()

        if interface is None:
            interface = Configuration.interface
        if interface is None:
            raise Exception('Wireless interface must be defined (-i)')

        # Accept both string and list of interfaces
        if isinstance(interface, str):
            self.interfaces = [interface]
        elif isinstance(interface, list):
            self.interfaces = interface
        else:
            raise ValueError('Interface must be a string or list of strings')

        # Validate interface list is not empty
        if not self.interfaces:
            raise ValueError('Interface list cannot be empty')

        # Keep backward compatibility with single interface attribute
        self.interface = self.interfaces[0]

        self.channel = channel
        self.target_bssid = target_bssid
        self.enable_deauth = enable_deauth and not pmf_required
        self.pmf_required = pmf_required
        self.manage_interface = manage_interface
        self.band = band
        if active_monitor is None:
            active_monitor = bool(getattr(Configuration,
                                          'hcxdump_active_monitor', False))
        self.active_monitor = bool(active_monitor)
        self.exitoneapol = exitoneapol
        self.scope = scope
        self.log_path = None
        # Bytes already in that log when this spawn started: the log is per
        # scope and appended across spawns, so anything before this offset
        # belongs to an earlier hcxdumptool session.
        self._log_offset = 0
        self._bpf_file = None
        # Interfaces handed back to managed mode for hcxdumptool; re-armed
        # on __exit__ so the rest of wifite keeps its monitor interface.
        self._monitor_restore = []

        # Generate output file if not provided
        if output_file is None:
            self.output_file = os.path.join(Configuration.temp(), 'hcxdumptool_capture.pcapng')
        else:
            self.output_file = output_file

        self.pid = None
        self.proc = None

        # Baseline size of the empty capture (pcapng Section Header / Interface
        # Description blocks are written the instant capture starts). Recorded
        # in __enter__ so has_captured_data()/has_new_data() can tell a
        # header-only file apart from one that actually contains frames.
        self._baseline_size = None
        # High-water mark of file size seen by has_new_data().
        self._last_data_size = 0

    @staticmethod
    def _driver_name(interface: str):
        """Return the kernel driver name for an interface, if available."""
        try:
            link = os.readlink(f'/sys/class/net/{interface}/device/driver')
            return os.path.basename(link)
        except OSError:
            return None

    def _mt76_interfaces(self):
        """Interfaces backed by mt76, where active monitor is unreliable."""
        return [iface for iface in self.interfaces
                if (self._driver_name(iface) or '').startswith('mt76')]

    _bpf_cache = {}

    def _install_target_bpf(self, bssid):
        """Compile and cache a BPF filter for the target BSSID.

        Returns the filter file path, or None when compilation is unsupported.
        """
        if not bssid:
            return None

        mac = bssid.replace(':', '').lower()
        cached = HcxDumpTool._bpf_cache.get(mac)
        if cached and os.path.exists(cached):
            return cached

        path = Configuration.temp('hcx_target_%s.bpf' % mac)
        try:
            code = Process(
                ['hcxdumptool', '--bpfc=wlan addr3 %s' % mac],
                devnull=False).stdout()
        except (OSError, RuntimeError) as error:
            log_warning('HcxDumpTool',
                        'BPF filter compilation failed: %s' % error)
            return None

        if not code or not code.strip():
            log_warning('HcxDumpTool', 'BPF filter compilation returned no code')
            return None

        try:
            with open(path, 'w') as handle:
                handle.write(code if code.endswith('\n') else code + '\n')
        except OSError as error:
            log_warning('HcxDumpTool', 'Could not write BPF filter: %s' % error)
            return None

        HcxDumpTool._bpf_cache[mac] = path
        return path

    def __enter__(self):
        """
        Start hcxdumptool capture process.
        Called at start of 'with HcxDumpTool(...) as x:'

        Optimizations:
        - Uses efficient BPF filters to reduce CPU usage
        - Filters for authentication frames only (SAE uses auth frames)
        - Reduces memory usage by filtering early in capture pipeline
        - Supports multiple interfaces for simultaneous monitoring
        """
        # hcxdumptool refuses to overwrite an existing capture file, so a
        # leftover file from a previous run would silently capture nothing.
        try:
            if os.path.exists(self.output_file):
                os.remove(self.output_file)
        except OSError:
            pass

        paired, pairing_warning = HcxDumpTool.check_tool_pairing()
        if not paired:
            log_warning('HcxDumpTool', pairing_warning)
            Color.pl('{!} {O}%s{W}' % pairing_warning)

        if self.manage_interface:
            self._monitor_restore = _hand_over_monitor_mode(self.interfaces)

        # Build the command
        # Note: hcxdumptool 7.x has simplified significantly
        # --rcascan is for scanning/assessment only (no capture)
        # -w is for capture mode (no scanning)
        # These options are mutually exclusive
        command = [
            'hcxdumptool',
            '-w', self.output_file,  # Changed from -o to -w for hcxdumptool 7.x compatibility
            # Headless: stdout is piped into the session log and never read,
            # so the real-time display only pads that log with AP rows.
            '--rds=0'
        ]

        # Add all interfaces with separate -i flags for multi-interface capture
        for iface in self.interfaces:
            command.extend(['-i', iface])

        # Channel needs an explicit band suffix: 1a (2.4 GHz), 36b (5 GHz), 5c (6 GHz)
        if self.channel:
            command.extend(['-c', channel_spec(self.channel, band=self.band)])

        # Restrict capture to the target BSSID so --exitoneapol cannot fire
        # on another network's pair. hcxdumptool recommends a target BPF
        # filter for --exitoneapol; without one we keep polling instead.
        if self.exitoneapol:
            bpf_file = self._install_target_bpf(self.target_bssid)
            if bpf_file:
                command.append('--bpf=%s' % bpf_file)
                command.append('--exitoneapol=%d' % int(self.exitoneapol))
            else:
                log_warning('HcxDumpTool',
                            '--exitoneapol skipped: no target BPF filter')

        # hcxdumptool transmits association/deauth/rogue M1M2 by default, so
        # "no deauth" has to disable those explicitly instead of merely
        # dropping -A. -A itself only ACKs incoming frames and requires
        # active monitor support; active monitor is broken on many mt76
        # drivers and can reduce capture to zero, so it is opt-in only.
        if not self.enable_deauth or self.pmf_required:
            command.extend(HcxDumpToolPassive.PASSIVE_OPTIONS)
        elif self.active_monitor:
            broken = self._mt76_interfaces()
            if broken:
                log_warning('HcxDumpTool',
                            f'Active monitor (-A) is unreliable on {broken[0]}; '
                            'capture may be empty')
                Color.pl('{!} {O}hcxdumptool: {C}-A{W} requested on {R}%s{O}; '
                         'active monitor is broken on this driver{W}' % broken[0])
            command.append('-A')

        # Start the process
        if self.scope:
            self.log_path = self.scope.create_log('hcxdumptool')
            try:
                self._log_offset = os.path.getsize(self.log_path)
            except OSError:
                self._log_offset = 0
            self.proc = self.scope.spawn(
                command, role='hcxdumptool', log_path=self.log_path)
        else:
            self.proc = Process(command, devnull=False)
        # Get the actual PID safely from the Popen object
        if self.proc and hasattr(self.proc, 'pid') and self.proc.pid and hasattr(self.proc.pid, 'pid'):
            self.pid = self.proc.pid.pid
        else:
            self.pid = None

        # Give it a moment to start
        time.sleep(1)

        # Record the header-only size now that the file exists, so subsequent
        # data checks measure growth beyond the pcapng header rather than
        # treating the always-present header as "captured data".
        try:
            self._baseline_size = os.path.getsize(self.output_file) \
                if os.path.exists(self.output_file) else 0
        except OSError:
            self._baseline_size = 0

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Stop hcxdumptool capture process.
        Called at end of 'with' block.
        """
        if self.proc and self.proc.poll() is None:
            if self.scope:
                self.proc.stop_owned()
            else:
                try:
                    self.proc.interrupt()
                    time.sleep(0.5)

                    if self.proc.poll() is None and self.pid is not None:
                        try:
                            os.kill(self.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                except Exception as e:
                    from ..util.logger import log_debug
                    log_debug('HcxDumpTool', f'Kill process error: {e}')

        _return_monitor_mode(self._monitor_restore)
        if self.scope:
            self.scope.unregister_health('hcxdumptool')

    def is_running(self) -> bool:
        """Check if hcxdumptool process is still running."""
        return self.proc is not None and self.proc.poll() is None

    def get_output_file(self) -> str:
        """Get the path to the capture output file."""
        return self.output_file

    def has_captured_data(self) -> bool:
        """Return True only when actual packet data exists beyond the header.

        A fresh pcapng file is non-empty the instant capture starts (the
        Section Header / Interface Description blocks are written immediately),
        so a bare ``getsize() > 0`` check is always true and meaningless. We
        compare against the header-only baseline recorded at start instead.
        """
        try:
            current = os.path.getsize(self.output_file)
        except OSError:
            return False
        baseline = self._baseline_size if self._baseline_size is not None else 0
        return current > baseline

    def has_new_data(self) -> bool:
        """Return True only when new packet data was written since the last call.

        Lets polling capture loops skip the expensive handshake validation
        (which spawns tshark / hcxpcapngtool / aircrack) when the capture file
        hasn't grown — i.e. there are no new frames worth re-evaluating.
        """
        try:
            current = os.path.getsize(self.output_file)
        except OSError:
            return False
        baseline = self._baseline_size if self._baseline_size is not None else 0
        if current > baseline and current > self._last_data_size:
            self._last_data_size = current
            return True
        return False

    def get_failure_reason(self, timeout: int = 2) -> str:
        """Return a human reason for a capture that stopped on its own.

        A supervised run (``scope``) sends both streams to ``log_path``,
        where ``Process.get_output()`` is empty by construction, so the log
        tail is the only source there. The read is bounded because that file
        may still be growing.
        """
        text = ''
        if self.log_path:
            try:
                offset = getattr(self, '_log_offset', 0) or 0
                with open(self.log_path, 'rb') as handle:
                    end = handle.seek(0, os.SEEK_END)
                    start = max(offset, end - 4096)
                    handle.seek(start)
                    text = handle.read(4096).decode('utf-8', errors='replace')
                    if start > offset:
                        # The window opened mid-line; that fragment is not
                        # this session's output.
                        text = text.split('\n', 1)[1] if '\n' in text else ''
            except OSError:
                text = ''

        if not text and self.proc:
            try:
                stdout, stderr = self.proc.get_output(timeout=timeout)
            except Exception:
                stdout, stderr = '', ''
            text = '\n'.join(
                part for part in ((stdout or ''), (stderr or '')) if part)

        if not text:
            return ''
        return _exit_reason(text) or _last_meaningful_line(text)

    @staticmethod
    def exists() -> bool:
        """Check if hcxdumptool is installed."""
        return Process.exists('hcxdumptool')

    @staticmethod
    def check_version() -> str:
        """
        Get hcxdumptool version.

        Returns:
            Version string or None if not installed
        """
        if not HcxDumpTool.exists():
            return None

        try:
            proc = Process(['hcxdumptool', '--version'], devnull=False)
            output = proc.stdout()

            # Parse version from output
            # Expected format: "hcxdumptool 6.x.x"
            import re
            match = re.search(r'(\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)

            return None
        except (OSError, RuntimeError):
            return None

    @staticmethod
    def check_tool_pairing():
        """Check that hcxdumptool and hcxpcapngtool are the same suite release.

        hcxtools requires both binaries to come from the same release;
        mixing them yields unreadable or silently missing hashes.

        Returns:
            (paired, warning): paired is False only when both versions are
            readable and disagree. Unknown versions are not an error.
        """
        try:
            dump_version = HcxDumpTool.check_version()
            cap_version = HcxPcapngTool.check_version()
            if not dump_version or not cap_version:
                return True, None

            def series(version):
                return '.'.join(str(version).split('.')[:2])

            if series(dump_version) != series(cap_version):
                return False, (
                    'hcxdumptool %s and hcxpcapngtool %s are from different '
                    'releases; install both from the same hcxtools suite' %
                    (dump_version, cap_version))
            return True, None
        except Exception:
            return True, None

    @staticmethod
    def check_minimum_version(min_version='7.0.0') -> bool:
        """
        Check if installed version meets minimum requirement.

        Args:
            min_version: Minimum required version (default: 7.0.0)

        Returns:
            True if version is sufficient, False otherwise
        """
        current = HcxDumpTool.check_version()
        if not current:
            return False

        try:
            current_parts = [int(x) for x in current.split('.')]
            min_parts = [int(x) for x in min_version.split('.')]

            return current_parts >= min_parts
        except ValueError:
            return False


class HcxDumpToolPassive:
    """
    Wrapper for hcxdumptool in receive-only ("passive") mode.

    hcxdumptool transmits by default. These options disable the active
    behaviors wifite promises not to use: association attempts, probe
    responses, disassociation frames, and rogue M1M2 replies.
    """

    PASSIVE_OPTIONS = (
        '--associationmax=0',       # never attempt to associate with an AP
        '--proberesponsetx=0',      # never transmit PROBERESPONSE frames
        '--disable_disassociation',  # never transmit DISASSOCIATION frames
        '--m2max=0',                # reject clients instead of rogue M1M2
    )

    def __init__(self, interface=None, output_file=None):
        """
        Initialize passive hcxdumptool wrapper.

        Args:
            interface: Wireless interface in monitor mode
            output_file: Output pcapng file path
        """
        Configuration.initialize()

        if interface is None:
            interface = Configuration.interface
        if interface is None:
            raise Exception('Wireless interface must be defined (-i)')

        self.interface = interface

        # Generate output file if not provided
        if output_file is None:
            self.output_file = os.path.join(Configuration.temp(), 'passive_pmkid.pcapng')
        else:
            self.output_file = output_file

        self.pid = None
        self.proc = None
        # Interfaces handed to hcxdumptool; re-armed on exit.
        self._monitor_restore = []

    def __enter__(self):
        """
        Start hcxdumptool in passive mode.
        Called at start of 'with HcxDumpToolPassive(...) as x:'
        """
        # Build the receive-only command for PMKID capture. The explicit
        # no-transmit flags are required: hcxdumptool is active by default.
        try:
            if os.path.exists(self.output_file):
                os.remove(self.output_file)
        except OSError:
            pass

        self._monitor_restore = _hand_over_monitor_mode([self.interface])

        command = [
            'hcxdumptool',
            '-i', self.interface,
            *self.PASSIVE_OPTIONS,
            '--rds=0',  # headless: the display is never read
            '-w', self.output_file,
        ]

        # Start the process
        self.proc = Process(command, devnull=False)
        # Get the actual PID safely from the Popen object
        if self.proc and hasattr(self.proc, 'pid') and self.proc.pid and hasattr(self.proc.pid, 'pid'):
            self.pid = self.proc.pid.pid
        else:
            self.pid = None

        # Give it a moment to start
        time.sleep(1)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Stop hcxdumptool gracefully.
        Called at end of 'with' block.
        """
        if self.proc and self.proc.poll() is None:
            # Send SIGTERM to gracefully stop
            try:
                self.proc.interrupt()
                time.sleep(0.5)

                # Force kill if still running
                if self.proc.poll() is None and self.pid is not None:
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # Process already exited
            except Exception as e:
                from ..util.logger import log_debug
                log_debug('HcxDumpToolPassive', f'Kill process error: {e}')

        _return_monitor_mode(self._monitor_restore)

    def is_running(self) -> bool:
        """Check if hcxdumptool process is still running."""
        return self.proc is not None and self.proc.poll() is None

    def get_capture_size(self) -> int:
        """
        Get current size of capture file in bytes.

        Returns:
            File size in bytes, or 0 if file doesn't exist
        """
        if os.path.exists(self.output_file):
            return os.path.getsize(self.output_file)
        return 0

    def get_failure_reason(self, timeout: int = 2) -> str:
        """Return a human reason for a capture that exited early."""
        if not self.proc:
            return ''
        try:
            stdout, stderr = self.proc.get_output(timeout=timeout)
        except Exception:
            return ''
        stdout = (stdout or '').strip()
        stderr = (stderr or '').strip()
        if not stdout and not stderr:
            return ''
        # Both streams are searched: hcxdumptool splits its summary and its
        # error text, and we do not know which one carries the stop line.
        reason = _exit_reason('\n'.join(part for part in (stdout, stderr) if part))
        if reason:
            return reason
        return _last_meaningful_line('\n'.join(part for part in (stdout, stderr) if part))


class HcxPcapngTool(Dependency):
    """Wrapper around hcxpcapngtool for converting captures to hashcat format."""

    dependency_required = False  # Optional for WPA3 attacks
    dependency_name = 'hcxpcapngtool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'

    @staticmethod
    def exists() -> bool:
        """Check if hcxpcapngtool is installed."""
        return Process.exists('hcxpcapngtool')

    @staticmethod
    def _remove_file(path: str) -> None:
        """Best-effort unlink; hcxpcapngtool appends to existing files."""
        if not path:
            return
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    @staticmethod
    def convert_to_hashcat(input_file: str, output_file: str,
                          bssid: str = None, essid: str = None) -> bool:
        """
        Convert pcapng capture to hashcat format (mode 22000).

        hcxpcapngtool 7+ no longer accepts --bssid/--essid, so matching
        records are filtered here after conversion: MAC_AP is field 3 and
        the hex-encoded ESSID is field 5 of a mode-22000 line.

        Args:
            input_file: Input pcapng file
            output_file: Output hash file
            bssid: Filter by BSSID (optional)
            essid: Filter by ESSID (optional)

        Returns:
            True if at least one matching hash was written, False otherwise
        """
        if not HcxPcapngTool.exists():
            return False

        HcxPcapngTool._remove_file(output_file)

        wants_filter = bool(bssid or essid)
        raw_output = f'{output_file}.raw' if wants_filter else output_file
        if wants_filter:
            HcxPcapngTool._remove_file(raw_output)

        command = [
            'hcxpcapngtool',
            '-o', raw_output,
            input_file
        ]

        try:
            proc = Process(command, devnull=False)
            return_code = proc.wait()
        except (OSError, RuntimeError):
            HcxPcapngTool._remove_file(raw_output)
            return False

        if return_code != 0:
            HcxPcapngTool._remove_file(raw_output)
            return False

        if wants_filter:
            try:
                with open(raw_output, errors='replace') as handle:
                    matches = filter_hash_lines(handle.readlines(), bssid, essid)
            except OSError:
                matches = []
            finally:
                HcxPcapngTool._remove_file(raw_output)

            if not matches:
                return False

            with open(output_file, 'w') as handle:
                handle.writelines(matches)

        return os.path.exists(output_file) and os.path.getsize(output_file) > 0

    @staticmethod
    def check_version() -> str:
        """
        Get hcxpcapngtool version.

        Returns:
            Version string or None if not installed
        """
        if not HcxPcapngTool.exists():
            return None

        try:
            proc = Process(['hcxpcapngtool', '--version'], devnull=False)
            output = proc.stdout()

            # Parse version from output
            import re
            match = re.search(r'(\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)

            return None
        except (OSError, RuntimeError):
            return None
