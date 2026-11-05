#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Network interface management for Evil Twin attacks.

Provides high-level interface management including AP mode detection,
configuration, IP assignment, and cleanup.
"""

import json
import os
import re
import threading
from typing import Optional
from dataclasses import dataclass, field

from ..tools.iw import Iw
from ..tools.ip import Ip
from ..tools.airmon import Airmon
from ..util.process import Process
from ..util.color import Color
from ..util.logger import log_info, log_error, log_warning, log_debug
from ..model.interface_info import InterfaceInfo
from ..config import Configuration


@dataclass
class InterfaceState:
    """
    Track interface state for cleanup and restoration.
    
    This class stores the original state of an interface before wifite
    modifies it, allowing proper restoration during cleanup.
    """
    name: str                           # Interface name
    original_mode: str                  # Original mode (managed, monitor, AP, etc.)
    original_up: bool                   # Whether interface was originally up
    original_mac: Optional[str]         # Original MAC address
    original_channel: Optional[int]     # Original channel
    current_mode: str                   # Current mode
    current_up: bool                    # Current up/down state
    managed_by_wifite: bool = True      # Whether wifite is managing this interface
    original_ips: list[str] = field(default_factory=list)
    original_ifindex: Optional[int] = None
    original_promisc: Optional[bool] = None
    original_allmulti: Optional[bool] = None
    changed_fields: set[str] = field(default_factory=set)
    added_ips: set[str] = field(default_factory=set)

    def __str__(self):
        return (f'{self.name}: original={self.original_mode}({"up" if self.original_up else "down"}), '
                f'current={self.current_mode}({"up" if self.current_up else "down"})')


@dataclass
class ForwardingState:
    original: bool
    written: bool


class InterfaceCapabilities:
    """Represents wireless interface capabilities."""
    
    def __init__(self, interface):
        self.interface = interface
        self.supports_ap_mode = False
        self.supports_monitor_mode = False
        self.supports_managed_mode = False
        self.phy = None
        self.driver = None
        self.chipset = None
        self.mac_address = None
        
        self._detect_capabilities()
    
    def _detect_capabilities(self):
        """Detect interface capabilities using iw."""
        try:
            # Get PHY info
            output = Process(['iw', 'dev', self.interface, 'info']).stdout()
            
            # Extract PHY
            if match := re.search(r'wiphy\s+(\d+)', output):
                self.phy = f'phy{match.group(1)}'
            
            # Get MAC address
            try:
                self.mac_address = Ip.get_mac(self.interface)
            except Exception as e:
                log_debug('InterfaceManager', f'Failed to get MAC for {self.interface}: {e}')
            
            # Get driver and chipset info from airmon
            iface_info = Airmon.get_iface_info(self.interface)
            if iface_info:
                self.driver = iface_info.driver
                self.chipset = iface_info.chipset
            
            # Check supported modes using iw phy
            if self.phy:
                phy_output = Process(['iw', 'phy', self.phy, 'info']).stdout()
                
                # Look for supported interface modes
                in_modes_section = False
                for line in phy_output.split('\n'):
                    if 'Supported interface modes:' in line:
                        in_modes_section = True
                        continue
                    
                    if in_modes_section:
                        if line.strip() and not line.startswith('\t'):
                            # End of modes section
                            break
                        
                        if '* AP' in line or '* master' in line:
                            self.supports_ap_mode = True
                        if '* monitor' in line:
                            self.supports_monitor_mode = True
                        if '* managed' in line:
                            self.supports_managed_mode = True
            
            log_debug('InterfaceManager', 
                     f'{self.interface}: AP={self.supports_ap_mode}, '
                     f'Monitor={self.supports_monitor_mode}, '
                     f'Managed={self.supports_managed_mode}')
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to detect capabilities for {self.interface}: {e}', e)
    
    def __str__(self):
        modes = []
        if self.supports_ap_mode:
            modes.append('AP')
        if self.supports_monitor_mode:
            modes.append('Monitor')
        if self.supports_managed_mode:
            modes.append('Managed')
        
        return f'{self.interface} ({", ".join(modes)})'


class InterfaceManager:
    """
    Manages network interfaces for Evil Twin attacks.
    
    Handles interface mode changes, IP configuration, and cleanup.
    Tracks interface states for proper restoration.
    """
    
    def __init__(self):
        self.interface_states: dict[str, InterfaceState] = {}
        self.assigned_ips: dict[str, str] = {}
        self.managed_interfaces = {}
        self._state_lock = threading.RLock()
        self._forwarding_state: Optional[ForwardingState] = None

    @staticmethod
    def _canonical_mode(mode: Optional[str]) -> Optional[str]:
        if mode is None:
            return None
        normalized = mode.strip().lower().replace('_', '-')
        return {
            'ap': 'AP',
            'adhoc': 'ad-hoc',
            'ad-hoc': 'ad-hoc',
            'ibss': 'ad-hoc',
            'mesh-point': 'mesh',
            'mp': 'mesh',
        }.get(normalized, normalized)

    @classmethod
    def _mode_command(cls, interface: str, mode: str) -> Optional[list[str]]:
        canonical = cls._canonical_mode(mode)
        target = {
            'AP': '__ap',
            'ad-hoc': 'ibss',
            'mesh': 'mesh',
        }.get(canonical, canonical)
        if target not in ('managed', 'monitor', '__ap', 'ibss', 'mesh'):
            return None
        return ['iw', 'dev', interface, 'set', 'type', target]

    @staticmethod
    def _run_checked(command: list[str], description: str = None) -> bool:
        try:
            if description:
                log_debug('InterfaceManager', description)
            result = Process.run_simple(command)
        except Exception as e:
            log_error('InterfaceManager', f'Command failed: {command}: {e}', e)
            return False
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or '').strip()
            log_error('InterfaceManager',
                      f'Command exited {result.returncode}: {command}: {detail}')
            return False
        return True

    @staticmethod
    def _get_interface_ifindex(interface: str) -> Optional[int]:
        try:
            with open(f'/sys/class/net/{interface}/ifindex') as handle:
                return int(handle.read().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def _get_interface_addresses(interface: str) -> Optional[list[str]]:
        try:
            result = Process.run_simple(['ip', '-json', 'addr', 'show', 'dev', interface])
            if result.returncode != 0:
                return None
            addresses = []
            for link in json.loads(result.stdout or '[]'):
                for address in link.get('addr_info', []):
                    local = address.get('local')
                    prefix = address.get('prefixlen')
                    if local is not None and prefix is not None:
                        addresses.append(f'{local}/{prefix}')
            return addresses
        except Exception:
            return None

    @staticmethod
    def _read_ip_forwarding() -> Optional[bool]:
        try:
            with open('/proc/sys/net/ipv4/ip_forward') as handle:
                value = handle.read().strip()
            if value not in ('0', '1'):
                return None
            return value == '1'
        except OSError:
            return None

    @staticmethod
    def _write_ip_forwarding(enabled: bool) -> bool:
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as handle:
                handle.write('1\n' if enabled else '0\n')
            return True
        except OSError:
            return False

    def _claim_interface(self, interface: str) -> bool:
        return self.is_managed(interface) or self._save_interface_state(interface)

    @staticmethod
    def _record_change(state: InterfaceState, field_name: str, original, current) -> None:
        if current == original:
            state.changed_fields.discard(field_name)
        else:
            state.changed_fields.add(field_name)
    
    @staticmethod
    def _execute_verbose(command: list[str], description: str = None) -> Optional[str]:
        """
        Execute a command with verbose logging support.
        
        Task 11.5: Log all system commands executed and their outputs in verbose mode.
        
        Args:
            command: Command to execute as list of arguments
            description: Optional description of what the command does
            
        Returns:
            Command output (stdout) or None on error
        """
        try:
            if Configuration.verbose >= 2:
                if description:
                    log_debug('InterfaceManager', f'Executing command: {description}')
                log_debug('InterfaceManager', f'Command: {" ".join(command)}')
            result = Process.run_simple(command)
            if result.returncode != 0:
                log_warning('InterfaceManager',
                            f'Command exited {result.returncode}: {result.stderr.strip()}')
                return None
            output = result.stdout
            if Configuration.verbose >= 3 and output:
                log_debug('InterfaceManager', f'Command output:\n{output}')
            return output
        except Exception as e:
            log_error('InterfaceManager', f'Command execution failed: {e}', e)
            return None
    
    def _save_interface_state(self, interface: str) -> bool:
        """
        Save the current state of an interface for later restoration.
        
        This method captures the interface's current configuration before
        wifite makes any changes, allowing proper cleanup later.
        
        Args:
            interface: Interface name to save state for
            
        Returns:
            True if state was saved successfully, False otherwise
        """
        with self._state_lock:
            if interface in self.interface_states:
                return True
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)
                current_mode = self._get_interface_mode(interface)
                current_up = self._is_interface_up(interface)
                current_mac = self._get_interface_mac(interface)
                current_channel = self._get_interface_channel(interface)
                current_ips = self._get_interface_addresses(interface)
                current_ifindex = self._get_interface_ifindex(interface)
                current_flags = self._get_interface_flags(interface)

                if (current_mode in (None, '', 'unknown') or current_up is None or
                        current_mac in (None, '', 'unknown') or current_ips is None or
                        current_ifindex is None):
                    log_error('InterfaceManager',
                              f'Cannot snapshot {interface} completely; refusing to modify it')
                    return False

                state = InterfaceState(
                    name=interface,
                    original_mode=current_mode,
                    original_up=current_up,
                    original_mac=current_mac,
                    original_channel=current_channel,
                    current_mode=current_mode,
                    current_up=current_up,
                    original_ips=list(current_ips),
                    original_ifindex=current_ifindex,
                    original_promisc=(bool(current_flags & self.IFF_PROMISC)
                                      if current_flags is not None else None),
                    original_allmulti=(bool(current_flags & self.IFF_ALLMULTI)
                                       if current_flags is not None else None),
                )
                self.interface_states[interface] = state
                self.managed_interfaces[interface] = {
                    'interface': interface,
                    'mode': current_mode,
                    'up': current_up,
                    'mac': current_mac,
                    'ips': list(current_ips),
                    'ifindex': current_ifindex,
                }
                log_info('InterfaceManager', f'Saved state for {interface}: {state}')
                return True
            except Exception as e:
                log_error('InterfaceManager', f'Failed to save state for {interface}: {e}', e)
                return False
    
    def _update_interface_state(self, interface: str, mode: Optional[str] = None, 
                               up: Optional[bool] = None) -> bool:
        """
        Update the tracked state of an interface after making changes.
        
        Args:
            interface: Interface name
            mode: New mode (if changed)
            up: New up/down state (if changed)
            
        Returns:
            True if state was updated, False otherwise
        """
        try:
            if interface not in self.interface_states:
                log_warning('InterfaceManager', f'No saved state for {interface}, cannot update')
                return False
            
            state = self.interface_states[interface]
            
            # Task 11.5: Log all interface state changes in verbose mode
            if mode is not None:
                old_mode = state.current_mode
                state.current_mode = mode
                log_debug('InterfaceManager', f'Updated {interface} mode to {mode}')
                
                if Configuration.verbose >= 2:
                    log_debug('InterfaceManager', f'State change: {interface} mode: {old_mode} -> {mode}')
            
            if up is not None:
                old_up = state.current_up
                state.current_up = up
                log_debug('InterfaceManager', f'Updated {interface} up state to {up}')
                
                if Configuration.verbose >= 2:
                    log_debug('InterfaceManager', f'State change: {interface} up: {old_up} -> {up}')
            
            return True
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to update state for {interface}: {e}', e)
            return False
    
    def is_managed(self, interface: str) -> bool:
        """
        Check if an interface is currently managed by wifite.
        
        Args:
            interface: Interface name
            
        Returns:
            True if interface is managed, False otherwise
        """
        return interface in self.interface_states and \
               self.interface_states[interface].managed_by_wifite
    
    def get_managed_interfaces(self) -> list[str]:
        """
        Get list of all interfaces currently managed by wifite.
        
        Returns:
            List of interface names
        """
        return [name for name, state in self.interface_states.items() 
                if state.managed_by_wifite]
    
    # ========================================================================
    # Interface Configuration Methods (Task 10.2)
    # ========================================================================
    
    def bring_interface_up(self, interface: str) -> bool:
        return self.set_interface_up(interface, True)

    def set_interface_up(self, interface: str, up: bool) -> bool:
        with self._state_lock:
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)
                current = self._is_interface_up(interface)
                if current is None:
                    return False
                if current == up:
                    return True
                if not self._claim_interface(interface):
                    return False
                state = self.interface_states[interface]
                command = ['ip', 'link', 'set', interface, 'up' if up else 'down']
                if not self._run_checked(command):
                    return False
                observed = self._is_interface_up(interface)
                if observed != up:
                    log_error('InterfaceManager',
                              f'{interface} up-state readback is {observed}, expected {up}')
                    return False
                state.current_up = observed
                self._record_change(state, 'up', state.original_up, observed)
                log_info('InterfaceManager',
                         f'Configuration result: SUCCESS - {interface} up={observed}')
                return True
            except Exception as e:
                log_error('InterfaceManager', f'Could not set {interface} up={up}: {e}', e)
                return False
    
    def bring_interface_down(self, interface: str) -> bool:
        return self.set_interface_up(interface, False)
    
    def set_interface_mode(self, interface: str, mode: str) -> bool:
        with self._state_lock:
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)
                desired = self._canonical_mode(mode)
                command = self._mode_command(interface, desired)
                if command is None:
                    log_error('InterfaceManager', f'Unknown mode: {mode}')
                    return False
                current = self._canonical_mode(self._get_interface_mode(interface))
                if current is None:
                    return False
                if current == desired:
                    return True
                if not self._claim_interface(interface):
                    return False

                state = self.interface_states[interface]
                was_up = self._is_interface_up(interface)
                if was_up is None:
                    return False
                if was_up:
                    if not self._run_checked(['ip', 'link', 'set', interface, 'down']):
                        return False
                    state.current_up = False
                    state.changed_fields.add('up')

                state.changed_fields.add('mode')
                if not self._run_checked(command, f'Set {interface} to {desired} mode'):
                    if was_up:
                        self._run_checked(['ip', 'link', 'set', interface, 'up'])
                    return False
                if was_up and not self._run_checked(['ip', 'link', 'set', interface, 'up']):
                    return False

                observed = self._canonical_mode(self._get_interface_mode(interface))
                observed_up = self._is_interface_up(interface)
                if observed != desired:
                    log_error('InterfaceManager',
                              f'{interface} mode readback is {observed}, expected {desired}')
                    return False
                if observed_up is None or observed_up != was_up:
                    log_error('InterfaceManager',
                              f'{interface} did not return to up={was_up} after mode change')
                    return False

                state.current_mode = observed
                state.current_up = observed_up
                self._record_change(state, 'mode', self._canonical_mode(state.original_mode), observed)
                self._record_change(state, 'up', state.original_up, observed_up)
                log_info('InterfaceManager',
                         f'Configuration result: SUCCESS - {interface} is now in {observed} mode')
                return True
            except Exception as e:
                log_error('InterfaceManager', f'Could not set {interface} to {mode} mode: {e}', e)
                return False

    def hand_over_monitor(self, interface: str) -> bool:
        """
        Return a monitor-mode interface to managed mode for hcxdumptool.

        hcxdumptool 7+ owns the monitor lifecycle and refuses to arm an
        interface that a third party left in monitor mode. The decision is
        made from live ``iw`` output, never from the ownership ledger:
        external tools change the mode out-of-band, so a stale ledger would
        skip the handover and make the capture silently fail.

        Untracked interfaces are handed over without creating a snapshot;
        ``rearm_monitor`` puts them back when hcxdumptool exits.
        """
        with self._state_lock:
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)

                if self._canonical_mode(self._get_interface_mode(interface)) != 'monitor':
                    return False

                if self.is_managed(interface):
                    return self.set_interface_mode(interface, 'managed')

                was_up = self._is_interface_up(interface)
                if was_up is None:
                    return False
                if was_up and not self._run_checked(['ip', 'link', 'set', interface, 'down']):
                    return False
                if not self._run_checked(
                        ['iw', 'dev', interface, 'set', 'type', 'managed'],
                        f'Hand {interface} to hcxdumptool in managed mode'):
                    if was_up:
                        self._run_checked(['ip', 'link', 'set', interface, 'up'])
                    return False
                if was_up and not self._run_checked(['ip', 'link', 'set', interface, 'up']):
                    return False

                observed = self._canonical_mode(self._get_interface_mode(interface))
                if observed != 'managed':
                    log_error('InterfaceManager',
                              f'{interface} did not reach managed mode for handover '
                              f'(still {observed})')
                    return False

                log_info('InterfaceManager',
                         f'Handed {interface} to hcxdumptool in managed mode')
                return True
            except Exception as e:
                log_error('InterfaceManager',
                          f'Could not hand {interface} to hcxdumptool: {e}', e)
                return False

    def rearm_monitor(self, interface: str) -> bool:
        """Return an interface handed to hcxdumptool to monitor mode."""
        with self._state_lock:
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)

                if self.is_managed(interface):
                    return self.set_interface_mode(interface, 'monitor')

                if self._canonical_mode(self._get_interface_mode(interface)) == 'monitor':
                    return True

                was_up = self._is_interface_up(interface)
                if was_up is None:
                    return False
                if was_up and not self._run_checked(['ip', 'link', 'set', interface, 'down']):
                    return False
                if not self._run_checked(
                        ['iw', 'dev', interface, 'set', 'type', 'monitor'],
                        f'Re-arm {interface} in monitor mode'):
                    if was_up:
                        self._run_checked(['ip', 'link', 'set', interface, 'up'])
                    return False
                if was_up and not self._run_checked(['ip', 'link', 'set', interface, 'up']):
                    return False

                return self._canonical_mode(self._get_interface_mode(interface)) == 'monitor'
            except Exception as e:
                log_error('InterfaceManager',
                          f'Could not re-arm {interface} in monitor mode: {e}', e)
                return False

    def set_interface_channel(self, interface: str, channel: int) -> bool:
        with self._state_lock:
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)
                channel = int(channel)
                if not 1 <= channel <= 233:
                    return False
                current = self._get_interface_channel(interface)
                if current == channel:
                    return True
                if not self._claim_interface(interface):
                    return False
                state = self.interface_states[interface]
                state.changed_fields.add('channel')
                command = ['iw', 'dev', interface, 'set', 'channel', str(channel)]
                if not self._run_checked(command):
                    return False
                observed = self._get_interface_channel(interface)
                if observed != channel:
                    log_error('InterfaceManager',
                              f'{interface} channel readback is {observed}, expected {channel}')
                    return False
                self._record_change(state, 'channel', state.original_channel, observed)
                log_info('InterfaceManager',
                         f'Configuration result: SUCCESS - {interface} is on channel {observed}')
                return True
            except Exception as e:
                log_error('InterfaceManager', f'Could not set {interface} channel: {e}', e)
                return False

    def set_interface_mac(self, interface: str, mac: str) -> bool:
        with self._state_lock:
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)
                if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac):
                    return False
                mac = mac.upper()
                current = self._get_interface_mac(interface)
                if current in (None, 'unknown'):
                    return False
                if current.upper() == mac:
                    return True
                if not self._claim_interface(interface):
                    return False
                state = self.interface_states[interface]
                was_up = self._is_interface_up(interface)
                if was_up is None:
                    return False
                if was_up and not self._run_checked(['ip', 'link', 'set', interface, 'down']):
                    return False
                if was_up:
                    state.changed_fields.add('up')
                state.changed_fields.add('mac')
                command = ['ip', 'link', 'set', 'dev', interface, 'address', mac]
                if not self._run_checked(command):
                    if was_up:
                        self._run_checked(['ip', 'link', 'set', interface, 'up'])
                    return False
                if was_up and not self._run_checked(['ip', 'link', 'set', interface, 'up']):
                    return False
                observed = self._get_interface_mac(interface)
                observed_up = self._is_interface_up(interface)
                if observed in (None, 'unknown') or observed.upper() != mac:
                    return False
                if observed_up != was_up:
                    return False
                self._record_change(state, 'mac', state.original_mac, observed)
                self._record_change(state, 'up', state.original_up, observed_up)
                return True
            except Exception as e:
                log_error('InterfaceManager', f'Could not set {interface} MAC: {e}', e)
                return False

    def claim_interface(self, interface: str) -> bool:
        """Snapshot the interface before another component mutates it."""
        with self._state_lock:
            return self._claim_interface(interface)

    def record_mac_change(self, interface: str) -> bool:
        """Mark a MAC change performed by an external tool (e.g. macchanger)."""
        with self._state_lock:
            state = self.interface_states.get(interface)
            if state is None:
                return False
            current = self._get_interface_mac(interface)
            original = state.original_mac
            if current in (None, 'unknown') or original in (None, 'unknown'):
                return False
            if current.upper() != original.upper():
                state.changed_fields.add('mac')
            else:
                state.changed_fields.discard('mac')
            return True

    def set_interface_addresses(self, interface: str, addresses: list[str]) -> bool:
        with self._state_lock:
            try:
                from ..config.validators import validate_interface_name
                validate_interface_name(interface)
                desired = list(dict.fromkeys(addresses))
                current = self._get_interface_addresses(interface)
                if current is None:
                    return False
                if current == desired:
                    return True
                if not self._claim_interface(interface):
                    return False
                state = self.interface_states[interface]
                state.changed_fields.add('addresses')

                for address in current:
                    if address not in desired:
                        if not self._run_checked(['ip', 'addr', 'del', address, 'dev', interface]):
                            return False
                for address in desired:
                    if address not in current:
                        if not self._run_checked(['ip', 'addr', 'add', address, 'dev', interface]):
                            return False
                        state.added_ips.add(address)

                observed = self._get_interface_addresses(interface)
                if observed is None or set(observed) != set(desired):
                    log_error('InterfaceManager',
                              f'{interface} address readback {observed}, expected {desired}')
                    return False
                self._record_change(state, 'addresses', state.original_ips, observed)
                if len(desired) == 1:
                    self.assigned_ips[interface] = desired[0]
                return True
            except Exception as e:
                log_error('InterfaceManager', f'Could not set {interface} addresses: {e}', e)
                return False
    
    def configure_interface(self, interface: str, mode: Optional[str] = None,
                          channel: Optional[int] = None, up: Optional[bool] = None) -> bool:
        """
        Configure multiple aspects of an interface at once.
        
        This is a convenience method that combines multiple configuration
        operations while properly tracking state changes.
        
        Args:
            interface: Interface name
            mode: Mode to set (optional)
            channel: Channel to set (optional)
            up: Whether to bring interface up or down (optional)
            
        Returns:
            True if all operations successful, False otherwise
        """
        try:
            log_debug('InterfaceManager', f'Configuring {interface}')
            
            # Save state if not already managed
            if not self.is_managed(interface):
                self._save_interface_state(interface)
            
            success = True
            
            # Set mode if specified
            if mode is not None:
                if not self.set_interface_mode(interface, mode):
                    success = False
            
            # Set channel if specified
            if channel is not None:
                if not self.set_interface_channel(interface, channel):
                    success = False
            
            # Set up/down state if specified
            if up is not None:
                if up:
                    if not self.bring_interface_up(interface):
                        success = False
                else:
                    if not self.bring_interface_down(interface):
                        success = False
            
            if success:
                log_info('InterfaceManager', f'Successfully configured {interface}')
            else:
                log_warning('InterfaceManager', f'Some configuration operations failed for {interface}')
            
            return success
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to configure {interface}: {e}', e)
            return False
    
    @staticmethod
    def get_wireless_interfaces() -> list[str]:
        """
        Get list of all wireless interfaces.
        
        Returns:
            List of interface names
        """
        try:
            interfaces = []
            _iface_re = re.compile(r'^[a-zA-Z0-9_\-]{1,15}$')

            # Use iw to get all wireless interfaces
            output = Process(['iw', 'dev']).stdout()

            for line in output.split('\n'):
                if 'Interface' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        interface = parts[1]
                        # Validate name before use (SEC-010)
                        if _iface_re.match(interface):
                            interfaces.append(interface)
                        else:
                            log_debug('InterfaceManager', f'Ignoring invalid interface name from iw output: {interface!r}')

            log_info('InterfaceManager', f'Found {len(interfaces)} wireless interfaces')
            return interfaces
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to get wireless interfaces: {e}', e)
            return []
    
    @staticmethod
    def get_ap_capable_interfaces() -> list[InterfaceCapabilities]:
        """
        Get list of interfaces that support AP mode.
        
        Returns:
            List of InterfaceCapabilities objects for AP-capable interfaces
        """
        ap_interfaces = []
        
        for interface in InterfaceManager.get_wireless_interfaces():
            caps = InterfaceCapabilities(interface)
            if caps.supports_ap_mode:
                ap_interfaces.append(caps)
        
        log_info('InterfaceManager', f'Found {len(ap_interfaces)} AP-capable interfaces')
        return ap_interfaces
    
    @staticmethod
    def check_ap_mode_support(interface) -> bool:
        """
        Check if an interface supports AP mode.
        
        Args:
            interface: Interface name to check
            
        Returns:
            True if AP mode is supported, False otherwise
        """
        caps = InterfaceCapabilities(interface)
        return caps.supports_ap_mode
    
    def get_interface_state(self, interface) -> dict:
        """
        Get current state of an interface.
        
        Args:
            interface: Interface name
            
        Returns:
            Dictionary with interface state information
        """
        try:
            state = {
                'interface': interface,
                'up': False,
                'mode': 'unknown',
                'ip_addresses': [],
                'mac': None
            }
            
            # Check if interface is administratively up
            state['up'] = InterfaceManager._is_interface_up(interface)
            
            # Get MAC address
            import contextlib
            with contextlib.suppress(Exception):
                state['mac'] = Ip.get_mac(interface)
            
            # Get mode using iw
            import contextlib
            with contextlib.suppress(Exception):
                iw_output = Process(['iw', 'dev', interface, 'info']).stdout()
                if 'type AP' in iw_output or 'type master' in iw_output:
                    state['mode'] = 'AP'
                elif 'type monitor' in iw_output:
                    state['mode'] = 'monitor'
                elif 'type managed' in iw_output:
                    state['mode'] = 'managed'
            
            # Get IP addresses
            import contextlib
            with contextlib.suppress(Exception):
                ip_output = Process(['ip', 'addr', 'show', interface]).stdout()
                for line in ip_output.split('\n'):
                    if 'inet ' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            state['ip_addresses'].append(parts[1])
            
            return state
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to get state for {interface}: {e}', e)
            return {'interface': interface, 'error': str(e)}
    
    def configure_for_ap(self, interface, ip_address='192.168.100.1/24') -> bool:
        """
        Configure interface for AP mode.
        
        Args:
            interface: Interface to configure
            ip_address: IP address to assign (CIDR notation)
            
        Returns:
            True if successful, False otherwise
        """
        log_info('InterfaceManager', f'Configuration step: Configuring {interface} for AP mode')

        if not self.set_interface_up(interface, False):
            log_error('InterfaceManager',
                      f'Configuration result: FAILED - Could not bring {interface} down')
            return False
        if not self.set_interface_mode(interface, 'AP'):
            log_error('InterfaceManager',
                      f'Configuration result: FAILED - Could not set {interface} to AP mode')
            return False
        if not self.set_interface_addresses(interface, [ip_address]):
            log_error('InterfaceManager',
                      f'Configuration result: FAILED - Could not assign {ip_address} to {interface}')
            return False
        if not self.set_interface_up(interface, True):
            log_error('InterfaceManager',
                      f'Configuration result: FAILED - Could not bring {interface} up')
            return False

        self.assigned_ips[interface] = ip_address
        log_info('InterfaceManager',
                 f'Configuration result: SUCCESS - {interface} configured for AP mode with IP {ip_address}')
        return True
    
    # ========================================================================
    # Interface Cleanup Methods (Task 10.3)
    # ========================================================================
    
    def restore_interface_mode(self, interface: str) -> bool:
        """
        Restore interface to its original mode.
        
        Args:
            interface: Interface to restore
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if interface not in self.interface_states:
                log_warning('InterfaceManager', f'No saved state for {interface}')
                return False
            
            state = self.interface_states[interface]
            original_mode = state.original_mode
            
            log_debug('InterfaceManager', f'Restoring {interface} mode to {original_mode}')
            
            # Don't restore to AP mode (security consideration)
            if original_mode == 'AP':
                original_mode = 'managed'
                log_debug('InterfaceManager', 'Changing AP mode to managed for safety')
            
            # Don't restore to unknown mode (invalid)
            if original_mode == 'unknown':
                original_mode = 'managed'
                log_debug('InterfaceManager', 'Changing unknown mode to managed for safety')
            
            # Set mode
            return self.set_interface_mode(interface, original_mode)
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to restore mode for {interface}: {e}', e)
            return False
    
    def restore_interface_state(self, interface: str) -> bool:
        """
        Restore interface to its original up/down state.
        
        Args:
            interface: Interface to restore
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if interface not in self.interface_states:
                log_warning('InterfaceManager', f'No saved state for {interface}')
                return False
            
            state = self.interface_states[interface]
            original_up = state.original_up
            
            log_debug('InterfaceManager', f'Restoring {interface} up/down state to {original_up}')
            
            if original_up:
                return self.bring_interface_up(interface)
            else:
                return self.bring_interface_down(interface)
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to restore state for {interface}: {e}', e)
            return False
    
    def set_ip_forwarding(self, enabled: bool) -> bool:
        """
        Enable or disable IPv4 forwarding while tracking the original value.

        The original value is only recorded the first time wifite changes the
        setting, so nested callers cannot lose the pre-run value.
        """
        with self._state_lock:
            current = self._read_ip_forwarding()
            if current is None:
                log_error('InterfaceManager',
                          'Cannot read /proc/sys/net/ipv4/ip_forward')
                return False
            if current == enabled:
                return True

            if self._forwarding_state is not None:
                original = self._forwarding_state.original
            else:
                original = current

            if not self._write_ip_forwarding(enabled):
                log_error('InterfaceManager', 'Failed to update IPv4 forwarding')
                return False

            observed = self._read_ip_forwarding()
            if observed != enabled:
                log_error('InterfaceManager',
                          f'IPv4 forwarding readback is {observed}, expected {enabled}')
                return False

            self._forwarding_state = ForwardingState(original=original, written=enabled)
            log_info('InterfaceManager', f'IPv4 forwarding set to {int(enabled)}')
            return True

    def _restore_ip_forwarding(self) -> bool:
        with self._state_lock:
            state = self._forwarding_state
            if state is None:
                return True

            current = self._read_ip_forwarding()
            if current is None:
                log_error('InterfaceManager',
                          'Cannot read IPv4 forwarding during cleanup')
                return False

            if current != state.written:
                log_warning('InterfaceManager',
                            'IPv4 forwarding was changed externally; leaving it untouched')
                self._forwarding_state = None
                return True

            if state.written == state.original:
                self._forwarding_state = None
                return True

            if not self._write_ip_forwarding(state.original):
                log_error('InterfaceManager', 'Failed to restore IPv4 forwarding')
                return False

            observed = self._read_ip_forwarding()
            if observed != state.original:
                log_error('InterfaceManager',
                          f'IPv4 forwarding restore readback is {observed}, '
                          f'expected {state.original}')
                return False

            self._forwarding_state = None
            log_info('InterfaceManager',
                     f'IPv4 forwarding restored to {int(state.original)}')
            return True

    def restore_ip_forwarding(self) -> bool:
        """Restore IPv4 forwarding to the value recorded before this run."""
        with self._state_lock:
            return self._restore_ip_forwarding()

    def restore_interface(self, interface: str) -> bool:
        """
        Restore an interface to the snapshot taken before this run mutated it.

        Only fields recorded as changed are written. The interface identity
        (ifindex) is verified first so a removed/recreated interface is never
        silently reconfigured. Failed restores keep their state record so a
        later cleanup can retry.

        Args:
            interface: Interface to restore

        Returns:
            True if every changed field was restored and verified, False otherwise
        """
        with self._state_lock:
            if interface not in self.interface_states:
                log_warning('InterfaceManager', f'No saved state for {interface}')
                return False

            state = self.interface_states[interface]
            log_info('InterfaceManager', '=' * 60)
            log_info('InterfaceManager',
                     f'Cleanup operation: Restoring {interface} to original state')
            log_info('InterfaceManager',
                     f'Original state: mode={state.original_mode}, up={state.original_up}, '
                     f'mac={state.original_mac}, channel={state.original_channel}, '
                     f'ips={state.original_ips}')
            log_info('InterfaceManager', '=' * 60)

            current_ifindex = self._get_interface_ifindex(interface)
            if current_ifindex is None or current_ifindex != state.original_ifindex:
                log_error('InterfaceManager',
                          f'{interface} identity changed '
                          f'(ifindex {state.original_ifindex} -> {current_ifindex}); '
                          'refusing to restore another device')
                return False

            success = True
            brought_down = False

            # Diff the live device against the snapshot. External tools
            # (hcxdumptool, airmon-ng, airodump-ng) change mode/MAC/flags
            # out-of-band without touching changed_fields; trusting the
            # ledger alone leaves the radio in monitor mode with a spoofed
            # MAC while reporting success.
            live_mode = self._canonical_mode(self._get_interface_mode(interface))
            live_up = self._is_interface_up(interface)
            live_mac = self._get_interface_mac(interface)
            live_channel = self._get_interface_channel(interface)
            live_ips = self._get_interface_addresses(interface)
            live_flags = self._get_interface_flags(interface)
            if live_mode is None or live_up is None or live_ips is None:
                log_error('InterfaceManager',
                          f'Cannot read live state for {interface}; refusing to guess')
                return False

            original_mode = self._canonical_mode(state.original_mode)
            changed = set(state.changed_fields)
            if live_mode != original_mode:
                changed.add('mode')
            if live_up != state.original_up:
                changed.add('up')
            if (live_mac not in (None, 'unknown') and state.original_mac and
                    live_mac.upper() != state.original_mac.upper()):
                changed.add('mac')
            if (state.original_channel is not None and
                    live_channel is not None and
                    live_channel != state.original_channel and
                    original_mode != 'managed'):
                changed.add('channel')
            if set(live_ips) != set(state.original_ips):
                changed.add('addresses')
            if live_flags is not None:
                if (state.original_promisc is not None and
                        bool(live_flags & self.IFF_PROMISC) != state.original_promisc):
                    changed.add('promisc')
                if (state.original_allmulti is not None and
                        bool(live_flags & self.IFF_ALLMULTI) != state.original_allmulti):
                    changed.add('allmulti')

            needs_down = bool(changed & {'mode', 'mac'})
            if needs_down and live_up:
                log_info('InterfaceManager',
                         f'Cleanup step: Bringing {interface} down')
                if not self._run_checked(['ip', 'link', 'set', interface, 'down']):
                    log_error('InterfaceManager',
                              f'Cleanup failed: could not bring {interface} down')
                    return False
                brought_down = True

            if 'mac' in changed and state.original_mac:
                log_info('InterfaceManager',
                         f'Cleanup step: Restoring MAC {state.original_mac} on {interface}')
                if not self._run_checked(['ip', 'link', 'set', 'dev', interface,
                                          'address', state.original_mac]):
                    log_error('InterfaceManager', f'Failed to restore MAC on {interface}')
                    success = False
                else:
                    observed = self._get_interface_mac(interface)
                    if observed in (None, 'unknown') or \
                            observed.upper() != state.original_mac.upper():
                        log_error('InterfaceManager',
                                  f'MAC readback mismatch on {interface}: {observed}')
                        success = False

            if 'mode' in changed:
                log_info('InterfaceManager',
                         f'Cleanup step: Restoring {state.original_mode} mode on {interface}')
                command = self._mode_command(interface, state.original_mode)
                if command is None or not self._run_checked(
                        command, f'Restore {interface} to {state.original_mode} mode'):
                    log_error('InterfaceManager',
                              f'Failed to restore mode on {interface}')
                    success = False
                else:
                    observed = self._canonical_mode(self._get_interface_mode(interface))
                    if observed != self._canonical_mode(state.original_mode):
                        log_error('InterfaceManager',
                                  f'Mode readback mismatch on {interface}: {observed}')
                        success = False

            if 'channel' in changed and state.original_channel is not None:
                log_info('InterfaceManager',
                         f'Cleanup step: Restoring channel {state.original_channel} on {interface}')
                if not self._run_checked(['iw', 'dev', interface, 'set', 'channel',
                                          str(state.original_channel)]):
                    log_error('InterfaceManager',
                              f'Failed to restore channel on {interface}')
                    success = False
                else:
                    observed = self._get_interface_channel(interface)
                    if observed != state.original_channel:
                        log_error('InterfaceManager',
                                  f'Channel readback mismatch on {interface}: {observed}')
                        success = False

            if 'addresses' in changed:
                log_info('InterfaceManager',
                         f'Cleanup step: Restoring addresses {state.original_ips} on {interface}')
                original_ips = set(state.original_ips)
                run_added = {address for address in state.added_ips
                             if address not in original_ips}
                current_ips = self._get_interface_addresses(interface)
                if current_ips is None:
                    log_error('InterfaceManager',
                              f'Failed to read addresses on {interface}')
                    success = False
                else:
                    current = set(current_ips)
                    for address in sorted(run_added & current):
                        if not self._run_checked(['ip', 'addr', 'del', address, 'dev', interface]):
                            log_error('InterfaceManager',
                                      f'Failed to remove {address} from {interface}')
                            success = False
                    for address in sorted(original_ips - current):
                        if not self._run_checked(['ip', 'addr', 'add', address, 'dev', interface]):
                            log_error('InterfaceManager',
                                      f'Failed to re-add {address} to {interface}')
                            success = False

                    observed = self._get_interface_addresses(interface)
                    if observed is None:
                        success = False
                    elif not original_ips.issubset(set(observed)) or \
                            run_added & set(observed):
                        log_error('InterfaceManager',
                                  f'Address readback mismatch on {interface}: {observed}')
                        success = False

            if 'up' in changed or brought_down:
                if state.original_up:
                    if not self.set_interface_up(interface, True):
                        log_error('InterfaceManager',
                                  f'Cleanup failed: could not bring {interface} up')
                        success = False
                elif self._is_interface_up(interface):
                    if not self.set_interface_up(interface, False):
                        log_error('InterfaceManager',
                                  f'Cleanup failed: could not leave {interface} down')
                        success = False

            # Monitor mode leaves IFF_PROMISC/IFF_ALLMULTI set; switching back
            # to managed does not clear them, so restore them explicitly.
            for field, flag in (('promisc', self.IFF_PROMISC),
                                ('allmulti', self.IFF_ALLMULTI)):
                if field not in changed:
                    continue
                desired = (state.original_promisc if field == 'promisc'
                           else state.original_allmulti)
                if desired is None:
                    continue
                log_info('InterfaceManager',
                         f'Cleanup step: Setting {field}={desired} on {interface}')
                if not self._set_interface_flag(interface, flag, desired):
                    log_error('InterfaceManager',
                              f'{field} readback mismatch on {interface}')
                    success = False

            if success:
                success = self._verify_restored_state(interface, state, changed)

            if success:
                del self.interface_states[interface]
                self.assigned_ips.pop(interface, None)
                self.managed_interfaces.pop(interface, None)
                log_info('InterfaceManager',
                         f'Cleanup result: SUCCESS - {interface} fully restored')
            else:
                log_warning('InterfaceManager',
                            f'Cleanup result: PARTIAL - retaining {interface} state for retry')
            log_info('InterfaceManager', '=' * 60)
            return success

    def _verify_restored_state(self, interface: str, state: InterfaceState,
                               changed: set[str]) -> bool:
        """Re-read the device and confirm every restored field matches.

        A restore is only successful when the kernel agrees with the
        snapshot; otherwise the state record is retained for a retry.
        """
        if 'mode' in changed:
            observed = self._canonical_mode(self._get_interface_mode(interface))
            if observed != self._canonical_mode(state.original_mode):
                log_error('InterfaceManager',
                          f'{interface} mode is still {observed}, expected '
                          f'{state.original_mode}')
                return False

        if 'up' in changed:
            observed = self._is_interface_up(interface)
            if observed != state.original_up:
                log_error('InterfaceManager',
                          f'{interface} up-state is still {observed}, expected '
                          f'{state.original_up}')
                return False

        if 'mac' in changed:
            observed = self._get_interface_mac(interface)
            if observed in (None, 'unknown') or state.original_mac is None or \
                    observed.upper() != state.original_mac.upper():
                log_error('InterfaceManager',
                          f'{interface} MAC is still {observed}, expected '
                          f'{state.original_mac}')
                return False

        if 'channel' in changed:
            observed = self._get_interface_channel(interface)
            if observed != state.original_channel:
                log_error('InterfaceManager',
                          f'{interface} channel is still {observed}, expected '
                          f'{state.original_channel}')
                return False

        if 'addresses' in changed:
            observed = self._get_interface_addresses(interface)
            original_ips = set(state.original_ips)
            run_added = set(state.added_ips) - original_ips
            if observed is None or not original_ips.issubset(set(observed)) or \
                    run_added & set(observed):
                log_error('InterfaceManager',
                          f'{interface} addresses are still {observed}, expected '
                          f'{sorted(original_ips)}')
                return False

        if changed & {'promisc', 'allmulti'}:
            flags = self._get_interface_flags(interface)
            if flags is None:
                log_error('InterfaceManager',
                          f'Cannot read flags for {interface} during verification')
                return False
            if 'promisc' in changed and state.original_promisc is not None and \
                    bool(flags & self.IFF_PROMISC) != state.original_promisc:
                log_error('InterfaceManager',
                          f'{interface} promisc is still '
                          f'{bool(flags & self.IFF_PROMISC)}, expected '
                          f'{state.original_promisc}')
                return False
            if 'allmulti' in changed and state.original_allmulti is not None and \
                    bool(flags & self.IFF_ALLMULTI) != state.original_allmulti:
                log_error('InterfaceManager',
                          f'{interface} allmulti is still '
                          f'{bool(flags & self.IFF_ALLMULTI)}, expected '
                          f'{state.original_allmulti}')
                return False

        return True

    def _restore_interface_legacy(self, interface: str) -> bool:
        """
        Legacy restore path retained for compatibility.

        It has no complete snapshot, so it must never issue blind iw/ip writes.
        """
        log_error('InterfaceManager',
                  f'Refusing legacy restore for {interface}: no verified snapshot')
        return False

    def cleanup_all(self) -> int:
        """
        Restore all managed interfaces and IPv4 forwarding.

        Failed restores keep their state records so a later call can retry.

        Returns:
            Number of interfaces successfully restored
        """
        with self._state_lock:
            log_info('InterfaceManager', '=' * 60)
            log_info('InterfaceManager', 'Starting cleanup of all managed interfaces')
            log_info('InterfaceManager', '=' * 60)

            interfaces = self.get_managed_interfaces()

            if not interfaces:
                log_info('InterfaceManager', 'No managed interfaces to clean up')
                self._restore_ip_forwarding()
                return 0

            log_info('InterfaceManager',
                     f'Found {len(interfaces)} managed interface(s) to clean up: '
                     f'{", ".join(interfaces)}')

            success_count = 0
            failed_interfaces = []

            for interface in interfaces:
                log_info('InterfaceManager',
                         f'Cleaning up interface {success_count + len(failed_interfaces) + 1}'
                         f'/{len(interfaces)}: {interface}')
                try:
                    if self.restore_interface(interface):
                        success_count += 1
                        log_info('InterfaceManager', f'Successfully cleaned up {interface}')
                    else:
                        failed_interfaces.append(interface)
                        log_warning('InterfaceManager', f'Failed to clean up {interface}')
                except Exception as e:
                    failed_interfaces.append(interface)
                    log_error('InterfaceManager', f'Error cleaning up {interface}: {e}', e)

            self._restore_ip_forwarding()

            log_info('InterfaceManager', '=' * 60)
            if failed_interfaces:
                log_warning('InterfaceManager',
                            f'Cleanup complete: {success_count} succeeded, '
                            f'{len(failed_interfaces)} failed')
                log_warning('InterfaceManager',
                            f'Failed interfaces: {", ".join(failed_interfaces)}')
            else:
                log_info('InterfaceManager',
                         f'Cleanup complete: All {success_count} interface(s) successfully restored')
            log_info('InterfaceManager', '=' * 60)

            return success_count

    @staticmethod
    def select_ap_interface(preferred=None) -> Optional[str]:
        """
        Select an interface for AP mode.
        
        Args:
            preferred: Preferred interface name (optional)
            
        Returns:
            Selected interface name or None
        """
        ap_interfaces = InterfaceManager.get_ap_capable_interfaces()
        
        if not ap_interfaces:
            Color.pl('{!} {R}No AP-capable interfaces found{W}')
            Color.pl('{!} {O}Your wireless adapter may not support AP mode{W}')
            return None
        
        # If preferred interface is specified and available, use it
        if preferred:
            for caps in ap_interfaces:
                if caps.interface == preferred:
                    log_info('InterfaceManager', f'Using preferred interface: {preferred}')
                    return preferred
            
            Color.pl('{!} {O}Preferred interface {R}%s{O} not found or not AP-capable{W}' % preferred)
        
        # If only one interface, use it
        if len(ap_interfaces) == 1:
            interface = ap_interfaces[0].interface
            Color.pl('{+} Using {G}%s{W} for AP mode' % interface)
            return interface
        
        # Multiple interfaces, ask user
        Color.pl('\n{+} {C}AP-capable interfaces:{W}')
        for idx, caps in enumerate(ap_interfaces, start=1):
            Color.pl('  {G}%d{W}. %s' % (idx, caps))
        
        Color.p('\n{+} Select interface for AP mode ({G}1-%d{W}): ' % len(ap_interfaces))
        try:
            choice = int(input())
            if 1 <= choice <= len(ap_interfaces):
                interface = ap_interfaces[choice - 1].interface
                log_info('InterfaceManager', f'User selected interface: {interface}')
                return interface
            else:
                Color.pl('{!} {R}Invalid selection{W}')
                return None
        except (ValueError, KeyboardInterrupt, EOFError):
            Color.pl('{!} {R}Selection cancelled{W}')
            return None
    
    def __del__(self):
        """Cleanup on deletion."""
        try:
            import contextlib
            with contextlib.suppress(Exception):
                self.cleanup_all()
        except ImportError:
            pass
    
    # ========================================================================
    # Interface Detection and Capability Checking (Task 2)
    # ========================================================================
    
    # Known driver lists for capability detection
    INJECTION_CAPABLE_DRIVERS = {
        'ath9k', 'ath9k_htc', 'ath10k', 'ath11k',
        'rt2800usb', 'rt2800pci', 'rt73usb', 'rt61pci',
        'rtl8812au', 'rtl8814au', 'rtl8821au', 'rtl88xxau',
        'carl9170', 'zd1211rw', 'p54usb', 'p54pci'
    }
    
    NO_INJECTION_DRIVERS = {
        'brcmfmac',  # Broadcom - limited injection
        'iwlwifi',   # Intel - no injection
        'rtw88',     # Realtek new driver - limited
    }
    
    AP_CAPABLE_DRIVERS = {
        'ath9k', 'ath9k_htc', 'ath10k', 'ath11k',
        'rt2800usb', 'rt2800pci', 'rt73usb', 'rt61pci',
        'rtl8812au', 'rtl8814au', 'rtl8821au', 'rtl88xxau',
        'brcmfmac', 'b43', 'iwlwifi'
    }
    
    # Driver to chipset mapping for common drivers
    DRIVER_CHIPSET_MAP = {
        'ath9k': 'Atheros AR9xxx',
        'ath9k_htc': 'Atheros AR9271',
        'ath10k': 'Qualcomm Atheros QCA9xxx',
        'ath11k': 'Qualcomm Atheros QCA6xxx',
        'rt2800usb': 'Ralink RT2800 USB',
        'rt2800pci': 'Ralink RT2800 PCI',
        'rt73usb': 'Ralink RT73',
        'rt61pci': 'Ralink RT61',
        'rtl8812au': 'Realtek RTL8812AU',
        'rtl8814au': 'Realtek RTL8814AU',
        'rtl8821au': 'Realtek RTL8821AU',
        'rtl88xxau': 'Realtek RTL88xxAU',
        'carl9170': 'Atheros AR9170',
        'zd1211rw': 'ZyDAS ZD1211',
        'p54usb': 'Prism54 USB',
        'p54pci': 'Prism54 PCI',
        'brcmfmac': 'Broadcom FullMAC',
        'iwlwifi': 'Intel Wireless',
        'rtw88': 'Realtek RTW88',
        'b43': 'Broadcom B43',
        'icnss2': 'Qualcomm ICNSS2'
    }
    
    @staticmethod
    def _get_interface_phy(interface: str) -> str:
        """
        Get physical device identifier for interface.
        
        Args:
            interface: Interface name
            
        Returns:
            PHY identifier (e.g., 'phy0') or 'unknown'
        """
        try:
            output = Process(['iw', 'dev', interface, 'info']).stdout()
            if match := re.search(r'wiphy\s+(\d+)', output):
                return f'phy{match.group(1)}'
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get PHY for {interface}: {e}')
        
        return 'unknown'
    
    @staticmethod
    def _get_interface_driver(interface: str) -> str:
        """
        Get driver name for interface using sysfs.
        
        Args:
            interface: Interface name
            
        Returns:
            Driver name or 'unknown'
        """
        try:
            # Try sysfs first (most reliable)
            driver_path = f'/sys/class/net/{interface}/device/driver'
            if os.path.exists(driver_path):
                driver_link = os.readlink(driver_path)
                driver = os.path.basename(driver_link)
                return driver
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get driver via sysfs for {interface}: {e}')
        
        try:
            # Fallback to airmon-ng
            iface_info = Airmon.get_iface_info(interface)
            if iface_info and iface_info.driver:
                return iface_info.driver
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get driver via airmon for {interface}: {e}')
        
        return 'unknown'
    
    @staticmethod
    def _get_interface_chipset(interface: str) -> str:
        """
        Get chipset description for interface.
        
        Args:
            interface: Interface name
            
        Returns:
            Chipset description or 'Unknown Chipset'
        """
        try:
            # Try airmon-ng first (has chipset info)
            iface_info = Airmon.get_iface_info(interface)
            if iface_info and iface_info.chipset:
                return iface_info.chipset
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get chipset via airmon for {interface}: {e}')
        
        # Fallback to driver-based mapping
        driver = InterfaceManager._get_interface_driver(interface)
        if driver in InterfaceManager.DRIVER_CHIPSET_MAP:
            return InterfaceManager.DRIVER_CHIPSET_MAP[driver]
        
        return 'Unknown Chipset'
    
    @staticmethod
    def _get_interface_mac(interface: str) -> str:
        """
        Get MAC address of interface.
        
        Args:
            interface: Interface name
            
        Returns:
            MAC address or 'unknown'
        """
        try:
            return Ip.get_mac(interface)
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get MAC for {interface}: {e}')
            return 'unknown'
    
    @staticmethod
    def _get_interface_mode(interface: str) -> str:
        """
        Get current operational mode of interface.
        
        Args:
            interface: Interface name
            
        Returns:
            Mode string ('managed', 'monitor', 'AP', etc.) or 'unknown'
        """
        try:
            # Use correct iw command syntax
            output = Process(['iw', 'dev', interface, 'info']).stdout()
            
            if 'type AP' in output or 'type master' in output:
                return 'AP'
            elif 'type monitor' in output:
                return 'monitor'
            elif 'type managed' in output:
                return 'managed'
            elif 'type IBSS' in output or 'type ad-hoc' in output:
                return 'ad-hoc'
            elif 'type mesh point' in output:
                return 'mesh'
            
            # Try to extract type from output
            if match := re.search(r'type\s+(\w+)', output):
                return match.group(1).lower()
                
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get mode for {interface}: {e}')
        
        return 'unknown'
    
    @staticmethod
    def _is_interface_up(interface: str) -> bool:
        """
        Check whether an interface is administratively up.

        Operstate ("state UP") reports link/carrier state, which is DOWN for
        monitor-mode and no-carrier interfaces even though the netdev is
        administratively up. Use the IFF_UP flag instead.

        Args:
            interface: Interface name

        Returns:
            True if administratively up, False otherwise
        """
        try:
            with open(f'/sys/class/net/{interface}/flags') as handle:
                return bool(int(handle.read().strip(), 16) & 0x1)
        except (OSError, ValueError):
            pass

        try:
            output = Process(['ip', 'link', 'show', interface]).stdout()
            if match := re.search(r'<([^>]*)>', output):
                return 'UP' in match.group(1).split(',')
            return False
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to check if {interface} is up: {e}')
            return False
    
    # netdev IFF_* bits exposed through /sys/class/net/<if>/flags.
    IFF_PROMISC = 0x100
    IFF_ALLMULTI = 0x200

    @staticmethod
    def _get_interface_flags(interface: str) -> Optional[int]:
        """
        Read the netdev flag word for an interface.

        Promiscuous/all-multicast are set implicitly when an interface enters
        monitor mode and are not cleared by switching back to managed, so they
        must be snapshotted and restored explicitly.

        Returns:
            Raw IFF_* flag word, or None when it cannot be read.
        """
        try:
            with open(f'/sys/class/net/{interface}/flags') as handle:
                return int(handle.read().strip(), 16)
        except (OSError, ValueError):
            pass

        try:
            output = Process(['ip', '-d', 'link', 'show', interface]).stdout()
            match = re.search(r'promiscuity\s+(\d+).*?allmulti\s+(\d+)', output, re.S)
            if match:
                flags = 0
                if int(match.group(1)):
                    flags |= InterfaceManager.IFF_PROMISC
                if int(match.group(2)):
                    flags |= InterfaceManager.IFF_ALLMULTI
                return flags
        except Exception as e:
            log_debug('InterfaceManager',
                      f'Failed to read flags for {interface}: {e}')
        return None

    def _set_interface_flag(self, interface: str, flag: int,
                            enabled: bool) -> bool:
        """Set an IFF_* flag and verify it through sysfs."""
        keyword = 'promisc' if flag == self.IFF_PROMISC else 'allmulticast'
        if not self._run_checked(['ip', 'link', 'set', 'dev', interface,
                                  keyword, 'on' if enabled else 'off']):
            return False
        observed = self._get_interface_flags(interface)
        if observed is None:
            return False
        return bool(observed & flag) == enabled

    @staticmethod
    def _is_interface_connected(interface: str) -> bool:
        """
        Check if interface is connected to a network.
        
        Args:
            interface: Interface name
            
        Returns:
            True if connected, False otherwise
        """
        try:
            output = Process(['iw', 'dev', interface, 'link']).stdout()
            # If connected, output contains "Connected to" or SSID info
            # If not connected, output contains "Not connected"
            return 'Not connected' not in output and ('Connected to' in output or 'SSID' in output)
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to check connection for {interface}: {e}')
            return False
    
    @staticmethod
    def _get_interface_frequency(interface: str) -> Optional[float]:
        """
        Get current frequency of interface in MHz.
        
        Args:
            interface: Interface name
            
        Returns:
            Frequency in MHz or None
        """
        try:
            output = Process(['iw', 'dev', interface, 'info']).stdout()
            # Look for frequency in format "channel X (YYYY MHz)"
            if match := re.search(r'channel\s+\d+\s+\((\d+)\s+MHz', output):
                return float(match.group(1))
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get frequency for {interface}: {e}')
        
        return None
    
    @staticmethod
    def _get_interface_channel(interface: str) -> Optional[int]:
        """
        Get current channel of interface.
        
        Args:
            interface: Interface name
            
        Returns:
            Channel number or None
        """
        try:
            output = Process(['iw', 'dev', interface, 'info']).stdout()
            # Look for channel in format "channel X"
            if match := re.search(r'channel\s+(\d+)', output):
                return int(match.group(1))
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get channel for {interface}: {e}')
        
        return None
    
    @staticmethod
    def _get_interface_tx_power(interface: str) -> Optional[int]:
        """
        Get TX power of interface in dBm.
        
        Args:
            interface: Interface name
            
        Returns:
            TX power in dBm or None
        """
        try:
            output = Process(['iw', 'dev', interface, 'info']).stdout()
            # Look for txpower in format "txpower XX.XX dBm"
            if match := re.search(r'txpower\s+([\d.]+)\s+dBm', output):
                return int(float(match.group(1)))
        except Exception as e:
            log_debug('InterfaceManager', f'Failed to get TX power for {interface}: {e}')
        
        return None
    
    @staticmethod
    def check_ap_mode_support(interface: str) -> bool:
        """
        Check if interface supports AP mode.
        
        Args:
            interface: Interface name
            
        Returns:
            True if AP mode is supported, False otherwise
        """
        try:
            # Get PHY for this interface
            phy = InterfaceManager._get_interface_phy(interface)
            
            if phy != 'unknown':
                # Query phy info for supported modes
                output = Process(['iw', 'phy', phy, 'info']).stdout()
                
                # Look for AP mode in supported interface modes
                in_modes_section = False
                for line in output.split('\n'):
                    if 'Supported interface modes:' in line:
                        in_modes_section = True
                        continue
                    
                    if in_modes_section:
                        # End of modes section
                        if line.strip() and not line.startswith('\t') and not line.startswith(' '):
                            break
                        
                        # Check for AP mode
                        if '* AP' in line or '* master' in line:
                            log_debug('InterfaceManager', f'{interface} supports AP mode (via iw phy)')
                            return True
            
            # Fallback: check against known AP-capable drivers
            driver = InterfaceManager._get_interface_driver(interface)
            if driver in InterfaceManager.AP_CAPABLE_DRIVERS:
                log_debug('InterfaceManager', f'{interface} supports AP mode (known driver: {driver})')
                return True
            
            log_debug('InterfaceManager', f'{interface} does not support AP mode')
            return False
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to check AP mode support for {interface}: {e}', e)
            # Conservative default: assume no AP support on error
            return False
    
    @staticmethod
    def check_monitor_mode_support(interface: str) -> bool:
        """
        Check if interface supports monitor mode.
        
        Args:
            interface: Interface name
            
        Returns:
            True if monitor mode is supported, False otherwise
        """
        try:
            # Check if already in monitor mode
            current_mode = InterfaceManager._get_interface_mode(interface)
            if current_mode == 'monitor':
                log_debug('InterfaceManager', f'{interface} already in monitor mode')
                return True

            # Broadcom FullMAC needs Nexmon firmware to expose monitor mode.
            driver = InterfaceManager._get_interface_driver(interface)
            if driver == 'brcmfmac':
                from ..tools.nexmon import Nexmon
                caps = Nexmon.probe(interface)
                supported = bool(caps and caps.native_monitor_ready)
                log_debug('InterfaceManager',
                          f'{interface} monitor via Nexmon: {supported}')
                return supported

            # Get PHY for this interface
            phy = InterfaceManager._get_interface_phy(interface)
            
            if phy != 'unknown':
                # Query phy info for supported modes
                output = Process(['iw', 'phy', phy, 'info']).stdout()
                
                # Look for monitor mode in supported interface modes
                in_modes_section = False
                for line in output.split('\n'):
                    if 'Supported interface modes:' in line:
                        in_modes_section = True
                        continue
                    
                    if in_modes_section:
                        # End of modes section
                        if line.strip() and not line.startswith('\t') and not line.startswith(' '):
                            break
                        
                        # Check for monitor mode (various formats)
                        if '* monitor' in line.lower() or 'monitor' in line.lower():
                            log_debug('InterfaceManager', f'{interface} supports monitor mode (from phy info)')
                            return True
            
            # Fallback: Most wireless interfaces support monitor mode
            # If we got this far and it's a wireless interface, assume support
            # This prevents false negatives from parsing issues
            log_debug('InterfaceManager', f'{interface} assumed to support monitor mode (wireless interface)')
            return True
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to check monitor mode support for {interface}: {e}', e)
            # On error, assume support for wireless interfaces (optimistic fallback)
            return True
    
    @staticmethod
    def test_monitor_mode(interface: str) -> bool:
        """
        Actually test if interface can enter monitor mode.
        This performs a real test by trying to set monitor mode.
        
        Args:
            interface: Interface name
            
        Returns:
            True if monitor mode can be enabled, False otherwise
        """
        try:
            # Save original mode
            original_mode = InterfaceManager._get_interface_mode(interface)
            log_debug('InterfaceManager', f'Testing monitor mode on {interface} (current mode: {original_mode})')
            
            # If already in monitor mode, it works
            if original_mode == 'monitor':
                log_debug('InterfaceManager', f'{interface} already in monitor mode')
                from ..util.color import Color
                if Configuration.verbose > 0:
                    Color.pl('{+} {G}%s already in monitor mode{W}' % interface)
                return True

            # Broadcom FullMAC requires the guarded Nexmon lifecycle.
            if InterfaceManager._get_interface_driver(interface) == 'brcmfmac':
                from ..tools.nexmon import Nexmon
                if os.geteuid() != 0:
                    log_debug('InterfaceManager',
                              f'Cannot live-test Nexmon monitor mode on {interface} without root')
                    return False
                success = Nexmon.self_test(interface)
                log_debug('InterfaceManager',
                          f'{interface} Nexmon monitor self-test: {success}')
                return success

            manager = Configuration.get_interface_manager()
            if not manager.set_interface_mode(interface, 'monitor'):
                log_debug('InterfaceManager',
                          f'{interface} failed to enter monitor mode')
                return False

            success = InterfaceManager._get_interface_mode(interface) == 'monitor'
            if not manager.restore_interface(interface):
                log_warning('InterfaceManager',
                            f'Failed to restore {interface} after monitor test; '
                            'cleanup will retry')

            if success:
                log_debug('InterfaceManager',
                          f'{interface} successfully tested monitor mode')
            else:
                log_debug('InterfaceManager',
                          f'{interface} failed monitor mode test')
            return success

        except Exception as e:
            log_error('InterfaceManager', f'Failed to test monitor mode for {interface}: {e}', e)
            return False
    
    @staticmethod
    def check_injection_support(interface: str) -> bool:
        """
        Check if interface supports packet injection.
        
        Args:
            interface: Interface name
            
        Returns:
            True if injection is supported, False otherwise
        """
        try:
            driver = InterfaceManager._get_interface_driver(interface)
            
            # Broadcom FullMAC only injects when Nexmon firmware is loaded.
            if driver == 'brcmfmac':
                from ..tools.nexmon import Nexmon
                caps = Nexmon.probe(interface)
                supported = bool(caps and caps.injection)
                log_debug('InterfaceManager',
                          f'{interface} injection via Nexmon: {supported}')
                return supported

            # Check against known problematic drivers
            if driver in InterfaceManager.NO_INJECTION_DRIVERS:
                log_debug('InterfaceManager', f'{interface} does not support injection (known driver: {driver})')
                return False
            
            # Check against known injection-capable drivers
            if driver in InterfaceManager.INJECTION_CAPABLE_DRIVERS:
                log_debug('InterfaceManager', f'{interface} supports injection (known driver: {driver})')
                return True
            
            # Unknown driver - optimistic default
            log_debug('InterfaceManager', f'{interface} assumed to support injection (unknown driver: {driver})')
            return True
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to check injection support for {interface}: {e}', e)
            # Optimistic default: assume injection support
            return True
    
    @staticmethod
    def get_available_interfaces() -> list[InterfaceInfo]:
        """
        Get all available wireless interfaces with their capabilities.
        
        This method enumerates all wireless interfaces on the system and
        gathers detailed information about each one, including capabilities
        and current state.
        
        Error Handling:
        - Catches exceptions during interface enumeration
        - Logs warnings for individual interface failures
        - Continues detection with remaining interfaces
        - Displays error message if no interfaces detected
        - Raises InterfaceNotFoundError if no interfaces found
        
        Returns:
            List of InterfaceInfo objects for all detected interfaces
            
        Raises:
            InterfaceNotFoundError: If no wireless interfaces are found
        """
        from .interface_exceptions import InterfaceNotFoundError
        from ..util.color import Color
        
        interfaces = []
        failed_interfaces = []
        
        try:
            # Task 11.1: Log start of interface detection
            log_info('InterfaceManager', '=' * 60)
            log_info('InterfaceManager', 'Starting wireless interface detection')
            log_info('InterfaceManager', '=' * 60)
            
            # Use Iw to enumerate wireless interfaces
            try:
                log_debug('InterfaceManager', 'Enumerating wireless interfaces using iw...')
                interface_names = Iw.get_interfaces()
                log_debug('InterfaceManager', f'iw returned {len(interface_names) if interface_names else 0} interface(s)')
            except Exception as e:
                log_error('InterfaceManager', f'Failed to enumerate interfaces: {e}', e)
                Color.pl('{!} {R}Error: Failed to enumerate wireless interfaces{W}')
                Color.pl('{!} {O}Make sure wireless tools (iw) are installed{W}')
                raise InterfaceNotFoundError(message=f'Failed to enumerate interfaces: {e}')
            
            if not interface_names:
                log_warning('InterfaceManager', 'No wireless interfaces found on system')
                Color.pl('{!} {R}No wireless interfaces found{W}')
                Color.pl('{!} {O}Make sure you have a wireless adapter connected{W}')
                raise InterfaceNotFoundError()
            
            # Task 11.1: Log each interface found with basic info
            log_info('InterfaceManager', f'Found {len(interface_names)} wireless interface(s): {", ".join(interface_names)}')
            
            # Get detailed information for each interface
            for interface_name in interface_names:
                try:
                    log_info('InterfaceManager', f'Detecting capabilities for {interface_name}...')
                    
                    interface_info = InterfaceManager._get_interface_info(interface_name)
                    
                    if interface_info:
                        interfaces.append(interface_info)
                        # Task 11.1: Log interface capabilities
                        log_info('InterfaceManager', 
                                f'  {interface_name}: {interface_info.get_capability_summary()}')
                        # Mask MAC address to avoid logging full hardware identifier
                        masked_mac = interface_info.mac_address
                        try:
                            if isinstance(interface_info.mac_address, str) and interface_info.mac_address:
                                parts = interface_info.mac_address.split(':')
                                if len(parts) == 6:
                                    masked_mac = ':'.join(parts[:3] + ['**', '**', '**'])
                        except Exception:
                            pass
                        log_debug('InterfaceManager', 
                                 f'  {interface_name} details: driver={interface_info.driver}, '
                                 f'chipset={interface_info.chipset}, phy={interface_info.phy}, '
                                 f'mac={masked_mac}')
                        log_debug('InterfaceManager', 
                                 f'  {interface_name} state: mode={interface_info.current_mode}, '
                                 f'up={interface_info.is_up}, connected={interface_info.is_connected}')
                    else:
                        # Interface info gathering failed
                        log_warning('InterfaceManager', 
                                   f'  {interface_name}: Failed to get interface info')
                        failed_interfaces.append((interface_name, 'Failed to gather information'))
                        
                except Exception as e:
                    # Don't fail entire detection for one interface
                    log_warning('InterfaceManager', 
                               f'  {interface_name}: Error during detection: {e}')
                    failed_interfaces.append((interface_name, str(e)))
                    continue
            
            # Task 11.1: Log total number of interfaces detected
            log_info('InterfaceManager', '-' * 60)
            log_info('InterfaceManager', 
                    f'Interface detection complete: {len(interfaces)} interface(s) successfully detected')
            
            if failed_interfaces:
                log_warning('InterfaceManager', 
                           f'Failed to detect {len(failed_interfaces)} interface(s)')
                for iface_name, error in failed_interfaces:
                    log_debug('InterfaceManager', f'  {iface_name}: {error}')
            
            log_info('InterfaceManager', '=' * 60)
            
            # Check if we got at least one valid interface
            if not interfaces:
                log_error('InterfaceManager', 'No valid wireless interfaces detected')
                Color.pl('{!} {R}No valid wireless interfaces detected{W}')
                
                if failed_interfaces:
                    Color.pl('{!} {O}Failed to detect the following interfaces:{W}')
                    for iface_name, error in failed_interfaces:
                        Color.pl('{!}   {C}%s{W}: {O}%s{W}' % (iface_name, error))
                
                raise InterfaceNotFoundError(message='No valid wireless interfaces detected')
            
        except InterfaceNotFoundError:
            # Re-raise our custom exception
            raise
        except Exception as e:
            log_error('InterfaceManager', f'Unexpected error during interface detection: {e}', e)
            Color.pl('{!} {R}Unexpected error during interface detection:{W} %s' % str(e))
            raise InterfaceNotFoundError(message=f'Interface detection failed: {e}')
        
        return interfaces
    
    @staticmethod
    def _get_interface_info(interface: str) -> Optional[InterfaceInfo]:
        """
        Get comprehensive information about an interface.
        
        Args:
            interface: Interface name
            
        Returns:
            InterfaceInfo object or None if interface is invalid
        """
        try:
            log_debug('InterfaceManager', f'Gathering information for {interface}')
            
            # Gather basic identification
            phy = InterfaceManager._get_interface_phy(interface)
            driver = InterfaceManager._get_interface_driver(interface)
            chipset = InterfaceManager._get_interface_chipset(interface)
            mac_address = InterfaceManager._get_interface_mac(interface)
            
            # Check capabilities
            supports_ap_mode = InterfaceManager.check_ap_mode_support(interface)
            supports_monitor_mode = InterfaceManager.check_monitor_mode_support(interface)
            supports_injection = InterfaceManager.check_injection_support(interface)
            
            # Get current state
            current_mode = InterfaceManager._get_interface_mode(interface)
            is_up = InterfaceManager._is_interface_up(interface)
            is_connected = InterfaceManager._is_interface_connected(interface)
            
            # Get optional details
            frequency = InterfaceManager._get_interface_frequency(interface)
            channel = InterfaceManager._get_interface_channel(interface)
            tx_power = InterfaceManager._get_interface_tx_power(interface)
            
            # Create InterfaceInfo object
            interface_info = InterfaceInfo(
                name=interface,
                phy=phy,
                driver=driver,
                chipset=chipset,
                mac_address=mac_address,
                supports_ap_mode=supports_ap_mode,
                supports_monitor_mode=supports_monitor_mode,
                supports_injection=supports_injection,
                current_mode=current_mode,
                is_up=is_up,
                is_connected=is_connected,
                frequency=frequency,
                channel=channel,
                tx_power=tx_power
            )
            
            log_debug('InterfaceManager', f'Interface info for {interface}: {interface_info.get_capability_summary()}')
            return interface_info
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to get interface info for {interface}: {e}', e)
            return None
