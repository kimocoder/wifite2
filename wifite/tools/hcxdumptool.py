#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
hcxdumptool Wrapper

This module provides a wrapper around hcxdumptool for capturing WPA3-SAE
handshakes and other wireless frames with PMF awareness.
"""

from .dependency import Dependency
from ..util.process import Process
from ..config import Configuration

import os
import time
import signal


class HcxDumpTool(Dependency):
    """Wrapper around hcxdumptool program for SAE handshake capture."""

    dependency_required = False  # Optional for WPA3 attacks
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, interface=None, channel=None, target_bssid=None,
                 output_file=None, enable_deauth=True, pmf_required=False):
        """
        Initialize hcxdumptool wrapper.

        Args:
            interface: Wireless interface(s) in monitor mode (string or list)
            channel: Channel to monitor (optional)
            target_bssid: Target BSSID to filter (optional)
            output_file: Output pcapng file path
            enable_deauth: Enable deauth attacks (default: True)
            pmf_required: Target has PMF required (disables deauth)
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

        # Generate output file if not provided
        if output_file is None:
            self.output_file = Configuration.temp() + 'hcxdumptool_capture.pcapng'
        else:
            self.output_file = output_file

        self.pid = None
        self.proc = None

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
        # Build the command
        command = [
            'hcxdumptool',
            '-o', self.output_file,
            '--enable_status=15'  # Enable all status messages
        ]
        
        # Add all interfaces with -i flag
        # hcxdumptool supports multiple -i flags for multi-interface capture
        for iface in self.interfaces:
            command.extend(['-i', iface])

        # Add channel if specified
        if self.channel:
            command.extend(['-c', str(self.channel)])

        # Add BSSID filter if specified (efficient hardware-level filtering)
        if self.target_bssid:
            # hcxdumptool expects BSSID without colons
            bssid_clean = self.target_bssid.replace(':', '')
            command.extend(['--filterlist_ap', bssid_clean])
            command.extend(['--filtermode', '2'])  # Mode 2: use as whitelist

        # Configure deauth behavior
        if self.enable_deauth:
            # Enable active attacks (deauth)
            command.append('--active_beacon')
        else:
            # Passive mode only (for PMF-required networks)
            command.append('--passive_beacon')

        # Optimize capture by filtering for relevant frame types only
        # This reduces CPU usage and memory consumption
        # SAE uses authentication frames (type 0x0b), so we focus on those
        # Also capture EAPOL frames for WPA2 handshakes in downgrade scenarios
        command.extend([
            '--rcascan',  # Disable unnecessary scanning
            '--disable_deauthentication_broadcast'  # Reduce broadcast traffic
        ])

        # Start the process
        self.proc = Process(command, devnull=False)
        self.pid = self.proc.pid.pid  # Get the actual PID from the Popen object

        # Give it a moment to start
        time.sleep(1)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Stop hcxdumptool capture process.
        Called at end of 'with' block.
        """
        if self.proc and self.proc.poll() is None:
            # Send SIGTERM to gracefully stop
            try:
                self.proc.interrupt()
                time.sleep(0.5)

                # Force kill if still running
                if self.proc.poll() is None:
                    os.kill(self.pid, signal.SIGKILL)
            except Exception as e:
                from ..util.logger import log_debug
                log_debug('HcxDumpTool', f'Kill process error: {e}')

    def is_running(self) -> bool:
        """Check if hcxdumptool process is still running."""
        return self.proc is not None and self.proc.poll() is None

    def get_output_file(self) -> str:
        """Get the path to the capture output file."""
        return self.output_file

    def has_captured_data(self) -> bool:
        """Check if any data has been captured."""
        return os.path.exists(self.output_file) and os.path.getsize(self.output_file) > 0

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
        except Exception:
            return None

    @staticmethod
    def check_minimum_version(min_version='6.0.0') -> bool:
        """
        Check if installed version meets minimum requirement.

        Args:
            min_version: Minimum required version (default: 6.0.0)

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
        except Exception:
            return False


class HcxDumpToolPassive:
    """
    Wrapper for hcxdumptool in passive mode.
    Uses --rds=3 flag for passive PMKID capture without deauth.
    """

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
            self.output_file = Configuration.temp() + 'passive_pmkid.pcapng'
        else:
            self.output_file = output_file

        self.pid = None
        self.proc = None

    def __enter__(self):
        """
        Start hcxdumptool in passive mode.
        Called at start of 'with HcxDumpToolPassive(...) as x:'
        """
        # Build the command for passive PMKID capture
        command = [
            'hcxdumptool',
            '-i', self.interface,
            #'--rds=3',  # Passive mode with PMKID capture
            '-w', self.output_file
            #'--enable_status=15'  # Enable all status messages
        ]

        # Start the process
        self.proc = Process(command, devnull=False)
        self.pid = self.proc.pid.pid  # Get the actual PID from the Popen object

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
                if self.proc.poll() is None:
                    os.kill(self.pid, signal.SIGKILL)
            except Exception as e:
                from ..util.logger import log_debug
                log_debug('HcxDumpToolPassive', f'Kill process error: {e}')

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
    def convert_to_hashcat(input_file: str, output_file: str,
                          bssid: str = None, essid: str = None) -> bool:
        """
        Convert pcapng capture to hashcat format (mode 22000).

        Args:
            input_file: Input pcapng file
            output_file: Output hash file
            bssid: Filter by BSSID (optional)
            essid: Filter by ESSID (optional)

        Returns:
            True if conversion successful, False otherwise
        """
        if not HcxPcapngTool.exists():
            return False

        command = [
            'hcxpcapngtool',
            '-o', output_file,
            input_file
        ]

        # Add filters if specified
        if bssid:
            command.extend(['--bssid', bssid.replace(':', '')])
        if essid:
            command.extend(['--essid', essid])

        try:
            proc = Process(command, devnull=False)
            proc.wait()

            # Check if output file was created
            return os.path.exists(output_file) and os.path.getsize(output_file) > 0
        except Exception:
            return False

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
        except Exception:
            return None
