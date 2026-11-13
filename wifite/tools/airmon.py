#!/usr/bin/env python
# -*- coding: utf-8 -*-

import glob
import os
import re
import signal
import subprocess
import time

from .dependency import Dependency
from .ip import Ip
from .iw import Iw
from ..config import Configuration
from ..util.color import Color
from ..util.errors import WifiteError
from ..util.input import interactive_input
from ..util.process import Process
from ..util.logger import log_debug


class AirmonIface:
    def __init__(self, phy, interface, driver, chipset):
        self.phy = phy
        self.interface = interface
        self.driver = driver
        self.chipset = chipset

    # Max length of fields.
    # Used for printing a table of interfaces.
    INTERFACE_LEN = 12
    PHY_LEN = 6
    DRIVER_LEN = 20
    CHIPSET_LEN = 30

    def __str__(self):
        """ Colored string representation of interface """
        s = ''
        s += Color.s(f'{self.interface.ljust(self.INTERFACE_LEN)}')
        s += Color.s(f'{self.phy.ljust(self.PHY_LEN)}')
        s += Color.s(f'{self.driver.ljust(self.DRIVER_LEN)}')
        s += Color.s(f'{self.chipset.ljust(self.CHIPSET_LEN)}')
        return s

    @staticmethod
    def menu_header():
        """ Colored header row for interfaces """
        s = '    ' + 'Interface'.ljust(AirmonIface.INTERFACE_LEN)
        s += 'PHY'.ljust(AirmonIface.PHY_LEN)
        s += 'Driver'.ljust(AirmonIface.DRIVER_LEN)
        s += 'Chipset'.ljust(AirmonIface.CHIPSET_LEN)
        s += '\n'
        s += '-' * \
             (AirmonIface.INTERFACE_LEN + AirmonIface.PHY_LEN + AirmonIface.DRIVER_LEN + AirmonIface.CHIPSET_LEN + 3)
        return s


class Airmon(Dependency):
    """ Wrapper around the 'airmon-ng' program """
    dependency_required = True
    dependency_name = 'airmon-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'
    chipset_table = 'https://wikidevi.com/wiki/Wireless_adapters/Chipset_table'
    base_interface = None
    killed_network_manager = False
    use_ipiw = False

    # see if_arp.h
    ARPHRD_ETHER = 1  # managed
    ARPHRD_IEEE80211_RADIOTAP = 803  # monitor

    def __init__(self):
        self.interfaces = None
        self.refresh()

    def refresh(self):
        """ Get airmon-recognized interfaces """
        self.interfaces = Airmon.get_interfaces()

    def print_menu(self):
        """ Prints menu """
        print((AirmonIface.menu_header()))
        for idx, interface in enumerate(self.interfaces, start=1):
            Color.pl(' {G}%d{W}. %s' % (idx, interface))

    def get(self, index):
        """ Gets interface at index (starts at 1) """
        if type(index) is str:
            index = int(index)
        return self.interfaces[index - 1]

    @staticmethod
    def get_interfaces():
        """Returns List of AirmonIface objects known by airmon-ng"""
        interfaces = []
        p2 = Process('airmon-ng')
        output = p2.stdout()
        log_debug('Airmon', 'airmon-ng output: %s' % output.strip())
        for line in output.split('\n'):
            # [PHY ]IFACE DRIVER CHIPSET
            airmon_re = re.compile(r'^(?:([^\t]*)\t+)?([^\t]*)\t+([^\t]*)\t+([^\t]*)$')
            matches = airmon_re.match(line)
            if not matches:
                continue

            phy, interface, driver, chipset = matches.groups()
            if phy in ['PHY', 'Interface']:
                continue

            if len(interface.strip()) == 0:
                continue

            interfaces.append(AirmonIface(phy, interface, driver, chipset))

        log_debug('Airmon', 'Found %d wireless interface(s)' % len(interfaces))
        for iface in interfaces:
            log_debug('Airmon', '  %s phy=%s driver=%s chipset=%s' % (
                iface.interface, iface.phy, iface.driver, iface.chipset))
        return interfaces

    @staticmethod
    def get_iface_info(interface_name):
        """
        Get interface info (driver, chipset), based on interface name.
        Returns an AirmonIface if interface name is found by airmon-ng or None
        """
        return next((intf_adapter for intf_adapter in Airmon.get_interfaces() if intf_adapter.interface == interface_name), None)

    @staticmethod
    def describe_interface(interface_name):
        """Return the interface name with its detected adapter model, if known."""
        physical_interface = Airmon.base_interface or interface_name
        iface_info = Airmon.get_iface_info(physical_interface)
        chipset = iface_info.chipset.strip() if iface_info and iface_info.chipset else ''

        if not chipset or chipset.lower().startswith('not '):
            driver = iface_info.driver.strip() if iface_info and iface_info.driver else ''
            if not driver:
                try:
                    from ..util.interface_manager import InterfaceManager
                    driver = InterfaceManager._get_interface_driver(physical_interface)
                except Exception:
                    driver = ''
            try:
                from ..util.interface_manager import InterfaceManager
                chipset = InterfaceManager.DRIVER_CHIPSET_MAP.get(driver, '')
            except Exception:
                chipset = ''

        return f'{interface_name} ({chipset})' if chipset else interface_name

    @staticmethod
    def require_interface(interface):
        """Fail fast when a user-supplied interface name is not a netdev.

        The radio-state owner refuses to snapshot a device it cannot read, so
        a wrong ``-i`` name would otherwise surface as a confusing "cannot
        snapshot" error instead of naming the real problem.
        """
        if os.path.isdir(os.path.join('/sys/class/net', interface)):
            return
        try:
            result = Process.run_simple(['ip', 'link', 'show', 'dev', interface])
            exists = result.returncode == 0
        except Exception:
            # Without sysfs or ip there is nothing reliable to check; let the
            # normal monitor-mode path report the driver error.
            return
        if exists:
            return

        wireless = [iface.interface for iface in Airmon.get_interfaces()]
        Color.pl('{!} {R}Interface {O}%s{R} does not exist{W}' % interface)
        if wireless:
            Color.pl('{!} {O}Available wireless interfaces:{W}')
            for name in wireless:
                Color.pl('{!}   - {G}%s{W}' % name)
            Color.pl('{!} {O}Re-run with {C}-i <interface>{O} using one of these names{W}')
        else:
            Color.pl('{!} {O}airmon-ng did not report any wireless interfaces{W}')
            Color.pl('{!} {O}Make sure your wireless device is connected{W}')
        raise WifiteError(f'Wireless interface {interface} not found')

    @staticmethod
    def start_monitor(interface):
        """Put interface into monitor mode through the state owner."""
        manager = Configuration.get_interface_manager()
        if not manager.set_interface_mode(interface, 'monitor'):
            Color.pl('{!} {O}Failed to put %s into monitor mode{W}' % interface)
            return None

        # Give the interface a moment to come up
        time.sleep(0.5)

        # /sys/class/net/wlan0/type
        iface_type_path = os.path.join('/sys/class/net', interface, 'type')
        if os.path.exists(iface_type_path):
            with open(iface_type_path) as f:
                iface_type = f.read().strip()
                if Configuration.verbose > 0:
                    Color.pl('{D}Interface type from sysfs: %s{W}' % iface_type)

        return interface

    @staticmethod
    def stop_monitor(interface):
        """Put interface back into managed mode through the state owner."""
        # Get driver info for ICNSS2 check
        iface_info = Airmon.get_iface_info(interface)
        if iface_info and iface_info.driver == 'icnss2':
            Color.p('{+} ICNSS2 driver detected for %s. Restoring station mode... ' % interface)
            # con_mode=0 recreates the normal managed interface. Restore it
            # directly; svc is unavailable in some supported environments.
            con_mode_paths = glob.glob('/sys/module/*/parameters/con_mode')
            if not con_mode_paths:
                Color.pl('{R}ICNSS2 con_mode parameter was not found{W}')
                return None
            try:
                with open(con_mode_paths[0], 'w') as handle:
                    handle.write('0')
            except OSError as e:
                Color.pl('{R}failed to restore ICNSS2 station mode: %s{W}' % e)
                return None

            # con_mode recreates wlan0; give the driver a moment before
            # bringing the managed interface up.
            time.sleep(0.5)
            try:
                result = Process.run_simple(
                    ['ip', 'link', 'set', interface, 'up'], timeout=10)
            except (OSError, subprocess.SubprocessError) as e:
                Color.pl('{R}could not bring restored interface up: %s{W}' % e)
                return None
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or '').strip()
                Color.pl('{R}could not bring restored interface up: %s{W}' % detail)
                return None

            from ..util.interface_manager import InterfaceManager
            for _ in range(50):
                if (not Iw.is_monitor(interface)
                        and InterfaceManager._is_interface_up(interface)):
                    Color.pl('{G}restored!{W}')
                    Color.pl('{+}{W} Disabled monitor mode on {G}%s{W}'
                             % Airmon.describe_interface(interface))
                    return interface
                time.sleep(0.2)

            Color.pl('{R}%s did not return to managed mode and up state{W}' % interface)
            return None

        manager = Configuration.get_interface_manager()
        if not manager.set_interface_mode(interface, 'managed'):
            Color.pl('{!} {O}Failed to return %s to managed mode{W}' % interface)
            return None

        return interface

    @classmethod
    def start(cls, interface):
        """
            Starts an interface (iface) in monitor mode
            Args:
                interface: Interface to start
            Returns:
                enabled_interface: Enabled interface
            Throws:
                Exception: If no interface is found
        """
        # Get interface name from input
        if type(interface) == AirmonIface:
            iface_name = interface.interface
            driver = interface.driver
        else:
            iface_name = interface
            driver = None # We'll try to fetch this if needed

        # Remember this as the 'base' interface.
        Airmon.base_interface = iface_name

        if driver is None:
            iface_obj = Airmon.get_iface_info(iface_name)
            if iface_obj:
                driver = iface_obj.driver

        # Broadcom FullMAC only supports monitor mode through Nexmon firmware.
        # Without Nexmon capabilities we keep the previous (likely failing) path
        # so behaviour on unpatched hardware is unchanged.
        if driver == 'brcmfmac':
            from .nexmon import Nexmon
            capabilities = Nexmon.probe(iface_name)
            if capabilities is not None and capabilities.native_monitor_ready:
                Color.p('{+} Enabling {G}Nexmon monitor mode{W} on {C}%s{W}... ' % iface_name)
                try:
                    monitor = Nexmon.start_monitor(iface_name)
                except Exception as e:
                    Color.pl('{R}failed (%s).{W}' % e)
                    raise WifiteError(f'Failed to enable Nexmon monitor mode on {iface_name}: {e}')
                cls.use_ipiw = True
                Color.pl('{G}enabled{W}!')
                return monitor

        # Try ICNSS2-specific activation first
        if iface_name == 'wlan0':
            # Try to get driver info if not already available
            if driver is None:
                iface_obj = Airmon.get_iface_info(iface_name)
                if iface_obj:
                    driver = iface_obj.driver

            if driver == 'icnss2':
                Color.p('{+} Attempting {G}ICNSS2 monitor mode{W} on {C}%s{W}... ' % iface_name)
                con_mode_paths = glob.glob('/sys/module/*/parameters/con_mode')
                if con_mode_paths:
                    con_mode_path = con_mode_paths[0]
                    try:
                        # con_mode recreates wlan0. Keep this transition out
                        # of InterfaceManager so it doesn't retain the old
                        # ifindex as the identity of the replacement netdev.
                        result = Process.run_simple(
                            ['ip', 'link', 'set', iface_name, 'down'])
                        if result.returncode != 0:
                            raise RuntimeError((result.stderr or result.stdout or '').strip())
                        with open(con_mode_path, 'w') as f:
                            f.write('4')
                        time.sleep(0.5)
                        result = Process.run_simple(
                            ['ip', 'link', 'set', iface_name, 'up'])
                        if result.returncode != 0:
                            raise RuntimeError((result.stderr or result.stdout or '').strip())
                        # Verify it's in monitor mode
                        if Iw.is_monitor(iface_name):
                            Color.pl('{G}enabled (ICNSS2 specific)!{W}')
                            cls.use_ipiw = True
                            return iface_name
                        else:
                            Color.pl('{O}failed (ICNSS2 specific, could not verify monitor mode). Trying other methods...{W}')
                            # Attempt to revert if possible, or let subsequent methods handle it
                    except subprocess.CalledProcessError as e:
                        Color.pl('{R}failed (ICNSS2 specific command error: %s). Trying other methods...{W}' % e.stderr.decode().strip())
                    except OSError as e:
                        Color.pl('{R}failed (ICNSS2 I/O error: %s). Trying other methods...{W}' % str(e))
                    except ValueError as e:
                        Color.pl('{R}failed (ICNSS2 config error: %s). Trying other methods...{W}' % str(e))
                    except Exception as e:
                        Color.pl('{R}failed (ICNSS2 unexpected error: %s). Trying other methods...{W}' % str(e))
                else:
                    Color.pl('{O}con_mode path not found for ICNSS2. Trying other methods...{W}')


        # Always use ip/iw method for better compatibility
        # This works for all drivers and is compatible with hcxdumptool (used for WPA3/PMKID)
        # airmon-ng creates interfaces that hcxdumptool doesn't work well with
        Color.p('{+} Enabling {G}monitor mode{W} on {C}%s{W}... ' % iface_name)

        enabled_interface = Airmon.start_monitor(iface_name)
        cls.use_ipiw = True

        # Verify monitor mode was enabled
        if enabled_interface is None:
            Color.pl('{R}failed to enable monitor mode using ip/iw.{W}')
            raise WifiteError('Failed to enable monitor mode')

        # Verify interface is actually in monitor mode
        if not Iw.is_monitor(enabled_interface):
            Color.pl('{R}interface %s not in monitor mode after ip/iw.{W}' % enabled_interface)
            raise Exception(f'Interface {enabled_interface} not in monitor mode after ip/iw')


        # No errors found; the device 'enabled_iface' was put into Mode:Monitor.
        Color.pl('{G}enabled{W}!')

        return enabled_interface

    @staticmethod
    def _parse_airmon_start(airmon_output):
        """Find the interface put into monitor mode (if any)"""
        # airmon-ng output examples:
        # (mac80211 monitor mode vif enabled for [phy10]wlan0 on [phy10]wlan0mon)
        # (mac80211 monitor mode already enabled for [phy0]wlxd037456283c3 on [phy0]10)
        # (mac80211 monitor mode vif enabled for [phy5]wlxd037456283c3 on [phy5]wlxd037456283c3mon)

        # Try to match from the "on" part first - this is the actual monitor interface
        # Updated regex to handle interface names that may contain numbers at the start
        enabled_on_re = re.compile(r'.*\(mac80211 monitor mode (?:(?:vif )?enabled|already enabled) (?:for [^ ]+ )?on (?:\[\w+])?([a-zA-Z][\w-]+(?:mon)?)\)?.*')

        # Fallback: try to match from the "for" part if "on" part is just numbers (channel)
        enabled_for_re = re.compile(r'.*\(mac80211 monitor mode (?:(?:vif )?enabled|already enabled) for (?:\[\w+])?(\w+).*on (?:\[\w+])?\d+\)?.*')
        lines = airmon_output.split('\n')

        for index, line in enumerate(lines):
            if 'mac80211 monitor mode' not in line:
                continue

            log_debug('Airmon', f'Parsing line: {repr(line)}')

            # First try to get interface from "on" part if it looks like an interface name
            if matches := enabled_on_re.match(line):
                result = matches.group(1)
                log_debug('Airmon', f'enabled_on_re matched: {repr(result)}')
                return result
            # Fallback to "for" part if "on" part is just a channel number
            elif matches := enabled_for_re.match(line):
                result = matches.group(1)
                log_debug('Airmon', f'enabled_for_re matched: {repr(result)}')
                return result
            # Legacy fallback
            elif "monitor mode enabled" in line:
                result = line.split()[-1]
                log_debug('Airmon', f'legacy fallback matched: {repr(result)}')
                return result
            else:
                log_debug('Airmon', 'No regex matched this line')

        return None

    @classmethod
    def stop(cls, interface):
        interface_label = cls.describe_interface(interface)
        Color.p('{!}{W} Disabling {O}monitor{W} mode on {R}%s{W}...\n'
                % interface_label)

        # A Nexmon session owns the monitor interface and must be torn down
        # through the wrapper so the station netdev is restored safely.
        from .nexmon import Nexmon
        if Nexmon.has_session(interface):
            if Nexmon.stop(interface):
                Color.pl('{+}{W} Disabled monitor mode on {G}%s{W}' % interface_label)
            else:
                Color.pl('{!} {O}Could not disable Nexmon monitor mode on {R}%s{W}'
                         % interface_label)
            return interface, interface

        iface_info = Airmon.get_iface_info(interface)
        is_icnss2 = bool(iface_info and iface_info.driver == 'icnss2')
        if cls.use_ipiw or is_icnss2:
            enabled_interface = disabled_interface = Airmon.stop_monitor(interface)
        else:
            airmon_output = Process(['airmon-ng', 'stop', interface]).stdout()
            disabled_interface, enabled_interface = Airmon._parse_airmon_stop(airmon_output)

        if disabled_interface and not is_icnss2:
            Color.pl('{+}{W} Disabled monitor mode on {G}%s{W}'
                     % cls.describe_interface(disabled_interface))
        elif not disabled_interface:
            Color.pl('{!} {O}Could not disable {R}%s{W}' % interface_label)

        return disabled_interface, enabled_interface

    @staticmethod
    def _parse_airmon_stop(airmon_output):
        """Find the interface taken out of into monitor mode (if any)"""
        # airmon-ng 1.2rc2 output: (mac80211 monitor mode vif enabled for [phy10]wlan0 on [phy10]wlan0mon)
        disabled_re = re.compile(r'\s*\(mac80211 monitor mode (?:vif )?disabled for (?:\[\w+])?(\w+)\)\s*')

        # airmon-ng 1.2rc1 output: wlan0mon (removed)
        removed_re = re.compile(r'([a-zA-Z\d]+).*\(removed\)')

        # Enabled interface: (mac80211 station mode vif enabled on [phy4]wlan0)
        enabled_re = re.compile(r'\s*\(mac80211 station mode (?:vif )?enabled on (?:\[\w+])?(\w+)\)\s*')

        disabled_interface = None
        enabled_interface = None
        for line in airmon_output.split('\n'):
            if matches := disabled_re.match(line):
                disabled_interface = matches.group(1)

            if matches := removed_re.match(line):
                disabled_interface = matches.group(1)

            if matches := enabled_re.match(line):
                enabled_interface = matches.group(1)

        return disabled_interface, enabled_interface

    @staticmethod
    def ask():
        """
        Asks user to define which wireless interface to use.
        Does not ask if:
            1. There is already an interface in monitor mode, or
            2. There is only one wireless interface (automatically selected).
        Puts selected device into Monitor Mode.
        """
        Airmon.terminate_conflicting_processes()

        Color.p('\n{+} Looking for {C}wireless interfaces{W}...')
        monitor_interfaces = Iw.get_interfaces(mode='monitor')
        if len(monitor_interfaces) == 1:
            # Assume we're using the device already in monitor mode
            interface = monitor_interfaces[0]
            iface_info = Airmon.get_iface_info(interface)
            if iface_info and iface_info.driver == 'brcmfmac':
                # Plain monitor on brcmfmac captures nothing without the
                # Nexmon radiotap mode.  The reuse path only ensures that
                # mode; it registers no session and takes no ownership of
                # the pre-existing interface.
                from .nexmon import Nexmon
                if Nexmon.probe(interface) is not None:
                    interface = Nexmon.start_monitor(interface)
            Color.clear_entire_line()
            Color.pl('{+} Using {G}%s{W} already in monitor mode' % interface)
            Airmon.base_interface = None
            return interface

        Color.clear_entire_line()
        Color.p('{+} Checking {C}airmon-ng{W}...')

        a = Airmon()
        if len(a.interfaces) == 0:
            # No interfaces found
            Color.pl('\n{!} {O}airmon-ng did not find {R}any{O} wireless interfaces')
            Color.pl('{!} {O}Make sure your wireless device is connected')
            Color.pl('{!} {O}See {C}https://www.aircrack-ng.org/doku.php?id=airmon-ng{O} for more info{W}')
            raise Exception('airmon-ng did not find any wireless interfaces')

        Color.clear_entire_line()
        a.print_menu()

        Color.pl('')

        if len(a.interfaces) == 1:
            # Only one interface, assume this is the one to use
            choice = 1
        else:
            # Multiple interfaces found
            Color.p('{+} Select wireless interface ({G}1-%d{W}): ' % len(a.interfaces))
            choice = interactive_input()

        selected = a.get(choice)

        if a.get(choice).interface in monitor_interfaces:
            Color.pl('{+} {G}%s{W} is already in monitor mode' % selected.interface)
        else:
            selected.interface = Airmon.start(selected)

        return selected.interface

    @staticmethod
    def terminate_conflicting_processes():
        """ Deletes conflicting processes reported by airmon-ng """
        airmon_output = Process(['airmon-ng', 'check']).stdout()

        # Checking for systemd, otherwise assume openrc

        if os.path.exists('/usr/lib/systemd/systemd'):
            init_system = 'systemd'
        else:
            init_system = 'openrc'
        # TODO: add support for other unorthodox init systems (maybe?)

        # Conflicting process IDs and names
        pid_pnames = []

        # 2272    dhclient
        # 2293    NetworkManager
        pid_pname_re = re.compile(r'^\s*(\d+)\s*([a-zA-Z\d_\-]+)\s*$')
        for line in airmon_output.split('\n'):
            if match := pid_pname_re.match(line):
                pid_pnames.append((match.group(1), match.group(2)))

        if not pid_pnames:
            return

        if not Configuration.kill_conflicting_processes:
            # Don't kill processes, warn user
            names_and_pids = ', '.join([f'{pname} ({pid})' for pid, pname in pid_pnames])
            Color.pl('{!} {O}Conflicting processes: %s' % names_and_pids)
            Color.pl('{!} {O}If you have problems: {R}kill -9 PID{O} or re-run wifite with {R}--kill{O}{W}')
            return

        Color.pl('{!} {O}Killing {R}%d {O}conflicting processes' % len(pid_pnames))
        for pid, pname in pid_pnames:
            if pname == 'NetworkManager' and Process.exists('systemctl'):
                Process(['systemctl', 'stop', 'NetworkManager']).stdout()
            elif pname == 'network-manager' and Process.exists('service'):
                Process(['service', 'network-manager', 'stop']).stdout()
            elif pname == 'avahi-daemon' and Process.exists('service'):
                Process(['service', 'avahi-daemon', 'stop']).stdout()
            else:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Process already exited
                except OSError:
                    pass  # Permission or other OS error

    @staticmethod
    def put_interface_up(interface):
        Color.p('{!}{W} Putting interface {R}%s{W} {G}up{W}...\n' % interface)
        Ip.up(interface)
        Color.pl('{+}{W} Done !')

    @staticmethod
    def put_interface_down(interface):
        """Bring an interface down (e.g. before changing mode/channel)."""
        Color.p('{!}{W} Putting interface {R}%s{W} {O}down{W}...\n' % interface)
        Ip.down(interface)
        Color.pl('{+}{W} Done !')

    @staticmethod
    def set_interface_mode(interface, mode_name):
        """Set an interface's 802.11 mode through the state owner."""
        log_debug('Airmon', f'Setting {interface} to {mode_name} mode')
        return Configuration.get_interface_manager().set_interface_mode(interface, mode_name)

    @staticmethod
    def get_interface_mode(interface):
        """Return the current 802.11 mode of an interface, or None.

        Parses `iw dev <iface> info` (e.g. 'type managed' / 'type monitor').
        """
        out, _err = Process.call(f'iw dev {interface} info')
        if match := re.search(r'^\s*type\s+(\w+)', out or '', re.MULTILINE):
            return match.group(1)
        return None

    @staticmethod
    def set_interface_channel(interface, channel):
        """Tune an interface to a channel through the state owner."""
        log_debug('Airmon', f'Setting {interface} to channel {channel}')
        return Configuration.get_interface_manager().set_interface_channel(interface, channel)

    @staticmethod
    def get_interface_channel(interface):
        """Return the current channel of an interface as int, or None.

        Parses `iw dev <iface> info` (e.g. 'channel 6 (2437 MHz)').
        """
        out, _err = Process.call(f'iw dev {interface} info')
        if match := re.search(r'^\s*channel\s+(\d+)', out or '', re.MULTILINE):
            return int(match.group(1))
        return None

    @staticmethod
    def start_network_manager():
        Color.p('{!} {O}start {R}NetworkManager{O}...')

        if Process.exists('service'):
            cmd = 'service networkmanager start'
            proc = Process(cmd)
            (out, err) = proc.get_output()
            if proc.poll() != 0:
                Color.pl(' {R}Error executing {O}%s{W}' % cmd)
                if out is not None and out.strip() != '':
                    Color.pl('{!} {O}STDOUT> %s{W}' % out)
                if err is not None and err.strip() != '':
                    Color.pl('{!} {O}STDERR> %s{W}' % err)
            else:
                Color.pl(' {G}Done{W} ({C}%s{W})' % cmd)
                return

        if Process.exists('systemctl'):
            cmd = 'systemctl start NetworkManager'
            proc = Process(cmd)
            (out, err) = proc.get_output()
            if proc.poll() != 0:
                Color.pl(' {R}Error executing {O}%s{W}' % cmd)
                if out is not None and out.strip() != '':
                    Color.pl('{!} {O}STDOUT> %s{W}' % out)
                if err is not None and err.strip() != '':
                    Color.pl('{!} {O}STDERR> %s{W}' % err)
            else:
                Color.pl(' {G}done{W} ({C}%s{W})' % cmd)
                return
        else:
            Color.pl(' {R}Cannot start NetworkManager: {O}systemctl{R} or {O}service{R} not found{W}')


if __name__ == '__main__':
    stdout = '''
Found 2 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to run 'airmon-ng check kill'

  PID Name
 5563 avahi-daemon
 5564 avahi-daemon

PHY	Interface	Driver		Chipset

phy0	wlx00c0ca4ecae0	rtl8187		Realtek Semiconductor Corp. RTL8187
Interface 15mon is too long for linux so it will be renamed to the old style (wlan#) name.

                (mac80211 monitor mode vif enabled on [phy0]wlan0mon
                (mac80211 station mode vif disabled for [phy0]wlx00c0ca4ecae0)
    '''
    start_iface = Airmon._parse_airmon_start(stdout)
    print(('start_iface from stdout:', start_iface))

    Configuration.initialize(False)
    iface = Airmon.ask()
    (disabled_iface, enabled_iface) = Airmon.stop(iface)
    print(('Disabled:', disabled_iface))
    print(('Enabled:', enabled_iface))

    print(f""""reaver" exists: {Process.exists('reaver')}""")

    # Test on never-ending process
    p = Process('yes')
    print('Running yes...')
    time.sleep(1)
    print('yes should stop now')
    p.interrupt()
