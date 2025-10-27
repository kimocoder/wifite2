#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Hostapd tool wrapper for creating software access points.
Used by Evil Twin attack to create rogue APs.
"""

import os
import time
import tempfile
from typing import Optional

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color
from ..util.logger import log_info, log_error, log_warning, log_debug


class Hostapd(Dependency):
    """
    Wrapper for hostapd to create software access points.
    """

    dependency_required = True
    dependency_name = 'hostapd'
    dependency_url = 'https://w1.fi/hostapd/'

    def __init__(self, interface, ssid, channel, password=None):
        """
        Initialize Hostapd configuration.

        Args:
            interface: Wireless interface for AP
            ssid: Network name
            channel: Wireless channel (1-11 for 2.4GHz)
            password: WPA2 password (None for open network)
        """
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.password = password or "temporarypassword123"

        self.config_file = None
        self.process = None
        self.running = False

        log_debug('Hostapd', f'Initialized for {ssid} on {interface} channel {channel}')

    @staticmethod
    def check_ap_mode_support(interface) -> bool:
        """
        Check if interface supports AP mode.

        Args:
            interface: Wireless interface to check

        Returns:
            True if AP mode is supported, False otherwise
        """
        try:
            # Use iw to check supported modes
            output = Process(['iw', interface, 'info']).stdout()

            # Check for AP mode in capabilities
            if 'AP' in output or 'master' in output:
                log_debug('Hostapd', f'{interface} supports AP mode')
                return True

            # Also check with iw list
            output = Process(['iw', 'list']).stdout()
            if 'AP' in output:
                log_debug('Hostapd', f'{interface} may support AP mode')
                return True

            log_warning('Hostapd', f'{interface} does not support AP mode')
            return False

        except Exception as e:
            log_error('Hostapd', f'Failed to check AP mode support: {e}', e)
            return False

    @staticmethod
    def get_ap_capable_interfaces():
        """
        Get list of interfaces that support AP mode.

        Returns:
            List of interface names
        """
        interfaces = []

        try:
            # Get all wireless interfaces
            output = Process(['iw', 'dev']).stdout()

            for line in output.split('\n'):
                if 'Interface' in line:
                    iface = line.split()[-1]
                    if Hostapd.check_ap_mode_support(iface):
                        interfaces.append(iface)

            log_info('Hostapd', f'Found {len(interfaces)} AP-capable interfaces')
            return interfaces

        except Exception as e:
            log_error('Hostapd', f'Failed to get AP-capable interfaces: {e}', e)
            return []

    def generate_config(self) -> str:
        """
        Generate hostapd configuration file content.

        Returns:
            Configuration file content as string
        """
        config = []

        # Basic settings
        config.append(f'interface={self.interface}')
        config.append('driver=nl80211')
        config.append(f'ssid={self.ssid}')
        config.append(f'channel={self.channel}')

        # Hardware mode (g = 2.4GHz)
        config.append('hw_mode=g')

        # IEEE 802.11n support
        config.append('ieee80211n=1')
        config.append('wmm_enabled=1')

        # Authentication
        config.append('auth_algs=1')

        # WPA2 settings
        config.append('wpa=2')
        config.append('wpa_key_mgmt=WPA-PSK')
        config.append('rsn_pairwise=CCMP')
        config.append(f'wpa_passphrase={self.password}')

        # Logging
        config.append('logger_syslog=-1')
        config.append('logger_syslog_level=2')
        config.append('logger_stdout=-1')
        config.append('logger_stdout_level=2')

        # Additional settings for stability
        config.append('ignore_broadcast_ssid=0')
        config.append('macaddr_acl=0')

        return '\n'.join(config) + '\n'

    def create_config_file(self) -> str:
        """
        Create temporary hostapd configuration file.

        Returns:
            Path to configuration file
        """
        try:
            # Create temp file
            fd, self.config_file = tempfile.mkstemp(
                prefix='hostapd_',
                suffix='.conf',
                dir=Configuration.temp()
            )

            # Write configuration
            config_content = self.generate_config()
            os.write(fd, config_content.encode('utf-8'))
            os.close(fd)

            # Set permissions
            os.chmod(self.config_file, 0o600)

            log_debug('Hostapd', f'Created config file: {self.config_file}')

            if Configuration.verbose > 1:
                Color.pl('{D}Hostapd config:{W}')
                for line in config_content.split('\n'):
                    if line.strip():
                        Color.pl('{D}  %s{W}' % line)

            return self.config_file

        except Exception as e:
            log_error('Hostapd', f'Failed to create config file: {e}', e)
            raise

    def start(self) -> bool:
        """
        Start hostapd process.

        Returns:
            True if started successfully, False otherwise
        """
        try:
            if self.running:
                log_warning('Hostapd', 'Already running')
                return True

            # Create config file
            if not self.config_file:
                self.create_config_file()

            # Prepare interface
            self._prepare_interface()

            # Start hostapd
            cmd = ['hostapd', self.config_file]

            if Configuration.verbose > 0:
                Color.pl('{+} Starting hostapd: {D}%s{W}' % ' '.join(cmd))

            self.process = Process(cmd, devnull=False)

            # Wait a moment for startup
            time.sleep(2)

            # Check if process is running
            if self.process.poll() is not None:
                # Process died
                output = self.process.stdout()
                log_error('Hostapd', f'Failed to start: {output}')
                Color.pl('{!} {R}Hostapd failed to start{W}')
                if Configuration.verbose > 0:
                    Color.pl('{!} {O}Output:{W}\n%s' % output)
                return False

            self.running = True
            log_info('Hostapd', f'Started successfully on {self.interface}')

            if Configuration.verbose > 0:
                Color.pl('{+} {G}Hostapd started{W} on {C}%s{W}' % self.interface)

            return True

        except Exception as e:
            log_error('Hostapd', f'Failed to start: {e}', e)
            Color.pl('{!} {R}Failed to start hostapd:{W} %s' % str(e))
            return False

    def _prepare_interface(self):
        """Prepare wireless interface for AP mode."""
        try:
            # Bring interface down
            Process(['ip', 'link', 'set', self.interface, 'down']).wait()

            # Set to AP mode (master mode)
            Process(['iw', self.interface, 'set', 'type', '__ap']).wait()

            # Bring interface up
            Process(['ip', 'link', 'set', self.interface, 'up']).wait()

            # Assign IP address
            Process(['ip', 'addr', 'flush', 'dev', self.interface]).wait()
            Process(['ip', 'addr', 'add', '192.168.100.1/24', 'dev', self.interface]).wait()

            log_debug('Hostapd', f'Prepared interface {self.interface}')

        except Exception as e:
            log_error('Hostapd', f'Failed to prepare interface: {e}', e)
            raise

    def stop(self):
        """Stop hostapd process."""
        try:
            if not self.running:
                return

            if Configuration.verbose > 0:
                Color.pl('{+} Stopping hostapd...')

            # Stop process
            if self.process and self.process.poll() is None:
                self.process.interrupt()
                time.sleep(1)

                # Force kill if still running
                if self.process.poll() is None:
                    self.process.kill()

            self.running = False
            log_info('Hostapd', 'Stopped')

        except Exception as e:
            log_error('Hostapd', f'Error stopping hostapd: {e}', e)

    def cleanup(self):
        """Cleanup hostapd resources."""
        try:
            # Stop process
            self.stop()

            # Remove config file
            if self.config_file and os.path.exists(self.config_file):
                os.remove(self.config_file)
                log_debug('Hostapd', f'Removed config file: {self.config_file}')

            # Restore interface
            self._restore_interface()

            log_info('Hostapd', 'Cleanup complete')

        except Exception as e:
            log_error('Hostapd', f'Cleanup error: {e}', e)

    def _restore_interface(self):
        """Restore interface to managed mode."""
        try:
            # Bring interface down
            Process(['ip', 'link', 'set', self.interface, 'down']).wait()

            # Flush IP addresses
            Process(['ip', 'addr', 'flush', 'dev', self.interface]).wait()

            # Set back to managed mode
            Process(['iw', self.interface, 'set', 'type', 'managed']).wait()

            # Bring interface up
            Process(['ip', 'link', 'set', self.interface, 'up']).wait()

            log_debug('Hostapd', f'Restored interface {self.interface}')

        except Exception as e:
            log_warning('Hostapd', f'Failed to restore interface: {e}')

    def is_running(self) -> bool:
        """
        Check if hostapd is running.

        Returns:
            True if running, False otherwise
        """
        if not self.process:
            return False

        return self.process.poll() is None

    def get_connected_clients(self):
        """
        Get list of connected clients.

        Returns:
            List of client MAC addresses
        """
        clients = []

        try:
            # Use hostapd_cli to get station list
            output = Process(['hostapd_cli', '-i', self.interface, 'all_sta']).stdout()

            for line in output.split('\n'):
                if line.startswith('sta['):
                    # Extract MAC address
                    mac = line.split('[')[1].split(']')[0]
                    clients.append(mac)

            return clients

        except Exception as e:
            log_debug('Hostapd', f'Failed to get connected clients: {e}')
            return []

    def __del__(self):
        """Cleanup on deletion."""
        try:
            self.cleanup()
        except:
            pass
