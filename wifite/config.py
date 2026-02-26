#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
from .util.color import Color
from .tools.macchanger import Macchanger


class Configuration(object):
    """ Stores configuration variables and functions for Wifite. """

    initialized = False  # Flag indicating config has been initialized
    verbose = 0
    version = '2.9.9-beta'

    all_bands = None
    attack_max = None
    check_handshake = None
    clients_only = None
    cracked_file = None
    crack_handshake = None
    daemon = None
    dont_use_pmkid = None
    encryption_filter = None
    existing_commands = None
    five_ghz = None
    ignore_cracked = None
    ignore_essids = None
    ignore_old_handshakes = None
    infinite_mode = None
    inf_wait_time = None
    interface = None
    kill_conflicting_processes = None
    manufacturers = None
    min_power = None
    no_deauth = None
    no_wps = None
    wps_no_nullpin = None
    num_deauths = None
    pmkid_timeout = None
    print_stack_traces = None
    random_mac = None
    random_mac_vendor = None
    require_fakeauth = None
    scan_time = None
    show_bssids = None
    show_cracked = None
    show_ignored = None
    update_db = None
    db_filename = None
    show_manufacturers = None
    skip_crack = None
    target_bssid = None
    target_channel = None
    target_essid = None
    temp_dir = None  # Temporary directory
    two_ghz = None
    use_bully = None
    use_reaver = None
    use_eviltwin = None
    # Dual interface support
    dual_interface_enabled = None
    interface_primary = None
    interface_secondary = None
    auto_assign_interfaces = None
    prefer_dual_interface = None
    use_hcxdump = None
    # Session resume flags
    resume = None
    resume_latest = None
    resume_id = None
    clean_sessions = None
    use_pmkid_only = None
    # Passive PMKID capture settings
    pmkid_passive = None
    pmkid_passive_duration = None
    pmkid_passive_interval = None
    wep_attacks = None
    wep_crack_at_ivs = None
    wep_filter = None
    wep_keep_ivs = None
    wep_pps = None
    wep_restart_aircrack = None
    wep_restart_stale_ivs = None
    wordlist = None
    wpa_attack_timeout = None
    wpa_deauth_timeout = None
    wpa_filter = None
    wpa_handshake_dir = None
    wpa_strip_handshake = None
    wps_fail_threshold = None
    wps_filter = None
    wps_ignore_lock = None
    wps_only = None
    wps_pin = None
    wps_pixie = None
    wps_pixie_timeout = None
    wps_timeout_threshold = None
    # TUI settings
    use_tui = None  # None = classic (default), True = force TUI, False = classic
    tui_refresh_rate = None
    tui_log_buffer_size = None
    # WPA-SEC upload settings
    wpasec_enabled = None
    wpasec_api_key = None
    wpasec_auto_upload = None
    wpasec_url = None
    wpasec_timeout = None
    wpasec_email = None
    wpasec_remove_after_upload = None
    # Attack monitoring settings
    monitor_attacks = None
    monitor_duration = None
    monitor_log_file = None
    monitor_channel = None
    monitor_hop = None

    @classmethod
    def initialize(cls, load_interface=True):
        """
            Sets up default initial configuration values.
            Also sets config values based on command-line arguments.
        """
        # TODO: categorize configuration into
        # separate classes (under config/*.py)
        # E.g. Configuration.wps.enabled,
        # Configuration.wps.timeout, etc

        # Only initialize this class once
        if cls.initialized:
            return
        cls.initialized = True

        cls.verbose = 0  # Verbosity of output. Higher number means more debug info about running processes.
        cls.print_stack_traces = True

        # Initialize logger early (will be configured with verbosity later)
        from .util.logger import Logger
        Logger.initialize(enabled=True)

        cls.kill_conflicting_processes = False

        cls.scan_time = 0  # Time to wait before attacking all targets

        cls.tx_power = 0  # Wifi transmit power (0 is default)
        cls.interface = None
        cls.min_power = 0  # Minimum power for an access point to be considered a target. Default is 0
        cls.attack_max = 0
        cls.skip_crack = False
        cls.target_channel = None  # User-defined channel to scan
        cls.target_essid = None  # User-defined AP name
        cls.target_bssid = None  # User-defined AP BSSID
        cls.ignore_essids = None  # ESSIDs to ignore
        cls.ignore_cracked = False  # Ignore previously-cracked BSSIDs
        cls.clients_only = False  # Only show targets that have associated clients
        cls.all_bands = False  # Scan for both 2Ghz and 5Ghz channels
        cls.two_ghz = False  # Scan 2.4Ghz channels
        cls.five_ghz = False  # Scan 5Ghz channels
        cls.infinite_mode = False  # Attack targets continuously
        cls.inf_wait_time = 60
        cls.show_bssids = False  # Show BSSIDs in targets list
        cls.show_manufacturers = False  # Show manufacturers in targets list
        cls.random_mac = False  # Should generate a random Mac address at startup.
        cls.no_deauth = False  # Deauth hidden networks & WPA handshake targets
        cls.num_deauths = 1  # Number of deauth packets to send to each target.
        cls.daemon = False  # Don't put back interface back in managed mode

        cls.encryption_filter = ['WEP', 'WPA', 'WPS']

        # EvilTwin variables
        cls.use_eviltwin = False
        cls.eviltwin_port = 80
        cls.eviltwin_deauth_iface = None
        cls.eviltwin_fakeap_iface = None
        cls.eviltwin_deauth_interval = 5
        cls.eviltwin_template = 'generic'
        cls.eviltwin_channel = None
        cls.eviltwin_validate_credentials = True

        # Dual interface support
        cls.dual_interface_enabled = False  # Enable dual interface mode
        cls.interface_primary = None  # Primary interface name
        cls.interface_secondary = None  # Secondary interface name
        cls.auto_assign_interfaces = True  # Auto-assign interfaces (default True)
        cls.prefer_dual_interface = True  # Prefer dual over single when available (default True)
        cls.use_hcxdump = False  # Use hcxdumptool for dual interface WPA capture (default False)

        # WEP variables
        cls.wep_filter = False  # Only attack WEP networks
        cls.wep_pps = 600  # Packets per second
        cls.wep_timeout = 600  # Seconds to wait before failing
        cls.wep_crack_at_ivs = 10000  # Minimum IVs to start cracking
        cls.require_fakeauth = False
        cls.wep_restart_stale_ivs = 11  # Seconds to wait before restarting
        # Aireplay if IVs don't increaes.
        # '0' means never restart.
        cls.wep_restart_aircrack = 30  # Seconds to give aircrack to crack
        # before restarting the process.
        cls.wep_crack_at_ivs = 10000  # Number of IVS to start cracking
        cls.wep_keep_ivs = False  # Retain .ivs files across multiple attacks.

        # WPA variables
        cls.wpa_filter = False  # Only attack WPA/WPA2 networks
        cls.wpa3_filter = False # Only attack WPA3 networks
        cls.owe_filter = False # Only attack OWE networks
        cls.wpa_deauth_timeout = 15  # Wait time between deauths
        cls.wpa_attack_timeout = 300  # Wait time before failing
        cls.wpa_handshake_dir = 'hs'  # Dir to store handshakes
        cls.wpa_strip_handshake = False  # Strip non-handshake packets
        cls.ignore_old_handshakes = False  # Always fetch a new handshake

        # WPA3-specific variables
        cls.wpa3_only = False  # Only attack WPA3-SAE networks, skip WPA2-only
        cls.wpa3_no_downgrade = False  # Disable transition mode downgrade attacks
        cls.wpa3_force_sae = False  # Skip WPA2 attacks on transition mode
        cls.wpa3_check_dragonblood = False  # Only scan for Dragonblood vulnerabilities
        cls.wpa3_attack_timeout = None  # WPA3-specific timeout (defaults to wpa_attack_timeout)

        # PMKID variables
        cls.use_pmkid_only = False  # Only use PMKID Capture+Crack attack
        cls.pmkid_timeout = 300  # Time to wait for PMKID capture
        cls.dont_use_pmkid = False  # Don't use PMKID attack

        # Passive PMKID capture variables
        cls.pmkid_passive = False  # Enable passive PMKID capture mode
        cls.pmkid_passive_duration = 0  # Duration for passive capture (0 = infinite)
        cls.pmkid_passive_interval = 30  # Interval between hash extractions in seconds

        # Default dictionary for cracking
        cls.cracked_file = 'cracked.json'
        cls.wordlist = None
        wordlists = [
            './wordlist-probable.txt',  # Local file (ran from cloned repo)
            '/usr/share/dict/wordlist-probable.txt',  # setup.py with prefix=/usr
            '/usr/local/share/dict/wordlist-probable.txt',  # setup.py with prefix=/usr/local
            # Other passwords found on Kali
            '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt',
            '/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt',
            '/usr/share/wordlists/fern-wifi/common.txt'
        ]
        for wlist in wordlists:
            if os.path.exists(wlist):
                cls.wordlist = wlist
                break

        if os.path.isfile('/usr/share/ieee-data/oui.txt'):
            manufacturers = '/usr/share/ieee-data/oui.txt'
        else:
            manufacturers = 'ieee-oui.txt'

        if os.path.exists(manufacturers):
            cls.manufacturers = {}
            with open(manufacturers, "r", encoding='utf-8') as f:
                # Parse txt format into dict
                for line in f:
                    if not re.match(r"^\w", line):
                        continue
                    line = line.replace('(hex)', '').replace('(base 16)', '')
                    fields = line.split()
                    if len(fields) >= 2:
                        cls.manufacturers[fields[0]] = " ".join(fields[1:]).rstrip('.')

        # WPS variables
        cls.wps_filter = False  # Only attack WPS networks
        cls.no_wps = False  # Do not use WPS attacks (Pixie-Dust & PIN attacks)
        cls.wps_only = False  # ONLY use WPS attacks on non-WEP networks
        cls.use_bully = False  # Use bully instead of reaver
        cls.use_reaver = False  # Use reaver instead of bully
        cls.wps_pixie = True
        cls.wps_no_nullpin = True
        cls.wps_pin = True
        cls.wps_ignore_lock = False  # Skip WPS PIN attack if AP is locked.
        cls.wps_pixie_timeout = 300  # Seconds to wait for PIN before WPS Pixie attack fails
        cls.wps_fail_threshold = 100  # Max number of failures
        cls.wps_timeout_threshold = 100  # Max number of timeouts

        # Commands
        cls.show_cracked = False
        cls.show_ignored = False
        cls.check_handshake = None
        cls.crack_handshake = False
        cls.update_db = False
        cls.db_filename = 'ieee-oui.txt'

        # Session resume
        cls.resume = False
        cls.resume_latest = False
        cls.resume_id = None
        cls.clean_sessions = False

        # TUI settings
        cls.use_tui = False  # False = classic (default), True = force TUI
        cls.tui_refresh_rate = 0.5  # Seconds between TUI updates
        cls.tui_log_buffer_size = 1000  # Maximum log entries to keep in memory
        cls.tui_color_scheme = 'default'  # Color scheme for TUI
        cls.tui_debug = False  # Enable TUI debug logging

        # WPA-SEC upload settings
        cls.wpasec_enabled = False  # Enable wpa-sec upload functionality
        cls.wpasec_api_key = None  # User API key for wpa-sec.stanev.org
        cls.wpasec_auto_upload = False  # Automatically upload without prompting
        cls.wpasec_url = 'https://wpa-sec.stanev.org'  # wpa-sec server URL
        cls.wpasec_timeout = 30  # Connection timeout in seconds
        cls.wpasec_email = None  # Optional email for notifications
        cls.wpasec_remove_after_upload = False  # Remove capture file after successful upload

        # Attack monitoring settings
        cls.monitor_attacks = False  # Enable wireless attack monitoring mode
        cls.monitor_duration = 0  # Duration for monitoring in seconds (0 = infinite)
        cls.monitor_log_file = None  # Log file path for attack events
        cls.monitor_channel = None  # Specific channel to monitor (None = current)
        cls.monitor_hop = False  # Enable channel hopping during monitoring

        # A list to cache all checked commands (e.g. `which hashcat` will execute only once)
        cls.existing_commands = {}

        # Overwrite config values with arguments (if defined)
        cls.load_from_arguments()

        if load_interface:
            cls.get_monitor_mode_interface()

    @classmethod
    def get_monitor_mode_interface(cls):
        if cls.interface is None:
            # Interface wasn't defined, select it!
            from .tools.airmon import Airmon
            cls.interface = Airmon.ask()
            if cls.random_mac or cls.random_mac_vendor:
                Macchanger.random(full_random=not cls.random_mac_vendor)

    @classmethod
    def load_from_arguments(cls):
        """ Sets configuration values based on Argument.args object """
        from .args import Arguments

        args = Arguments(cls).args
        cls.parse_settings_args(args)
        cls.parse_wep_args(args)
        cls.parse_wpa_args(args)
        cls.parse_wps_args(args)
        cls.parse_pmkid_args(args)
        cls.parse_eviltwin_args(args)
        cls.parse_attack_monitor_args(args)
        cls.parse_dual_interface_args(args)
        cls.parse_wpasec_args(args)
        cls.parse_encryption()

        cls.parse_wep_attacks()

        cls.validate()

        # Commands
        if args.cracked:
            cls.show_cracked = True
        if args.ignored:
            cls.show_ignored = True
        if args.check_handshake:
            cls.check_handshake = args.check_handshake
        if args.crack_handshake:
            cls.crack_handshake = True
        if args.update_db:
            cls.update_db = True

        # Session resume
        if args.resume:
            cls.resume = True
        if args.resume_latest:
            cls.resume_latest = True
        if args.resume_id:
            cls.resume_id = args.resume_id
        if args.clean_sessions:
            cls.clean_sessions = True
    @classmethod
    def validate(cls):
        if cls.use_pmkid_only and cls.wps_only:
            Color.pl('{!} {R}Bad Configuration:{O} --pmkid and --wps-only are not compatible')
            raise RuntimeError('Unable to attack networks: --pmkid and --wps-only are not compatible together')
        if cls.use_pmkid_only and cls.dont_use_pmkid:
            Color.pl('{!} {R}Bad Configuration:{O} --pmkid and --no-pmkid are not compatible')
            raise RuntimeError('Unable to attack networks: --pmkid and --no-pmkid are not compatible together')

        # Validate Evil Twin configuration
        if cls.use_eviltwin:
            cls._validate_eviltwin_config()

        # Validate attack monitoring configuration
        if cls.monitor_attacks:
            cls._validate_attack_monitor_config()

        # Validate wpa-sec configuration
        if cls.wpasec_enabled:
            cls._validate_wpasec_config()

    @classmethod
    def _validate_eviltwin_config(cls):
        """Validate Evil Twin configuration and interface capabilities."""
        from .util.interface_manager import InterfaceManager

        # Check if we have AP-capable interfaces
        ap_interfaces = InterfaceManager.get_ap_capable_interfaces()

        if not ap_interfaces:
            Color.pl('{!} {R}Error: No AP-capable wireless interfaces found{W}')
            Color.pl('{!} {O}Evil Twin attack requires a wireless adapter that supports AP mode{W}')
            Color.pl('{!} {O}Recommended adapters:{W}')
            Color.pl('{!}   - Alfa AWUS036NHA (Atheros AR9271)')
            Color.pl('{!}   - TP-Link TL-WN722N v1 (Atheros AR9271)')
            Color.pl('{!}   - Panda PAU05 (Ralink RT5372)')
            Color.pl('{!}   - Alfa AWUS036ACH (Realtek RTL8812AU)')
            raise RuntimeError('No AP-capable interfaces available for Evil Twin attack')

        # If fake AP interface is specified, validate it
        if cls.eviltwin_fakeap_iface:
            found = False
            for caps in ap_interfaces:
                if caps.interface == cls.eviltwin_fakeap_iface:
                    found = True
                    break

            if not found:
                Color.pl('{!} {R}Error: Specified interface {O}%s{R} does not support AP mode{W}'
                        % cls.eviltwin_fakeap_iface)
                Color.pl('{!} {O}Available AP-capable interfaces:{W}')
                for caps in ap_interfaces:
                    Color.pl('{!}   - {G}%s{W}' % caps.interface)
                raise RuntimeError('Specified interface does not support AP mode')

        # Validate port
        if cls.eviltwin_port < 1 or cls.eviltwin_port > 65535:
            Color.pl('{!} {R}Error: Invalid port {O}%d{W}' % cls.eviltwin_port)
            raise RuntimeError('Invalid port number for Evil Twin captive portal')

        # Validate deauth interval
        if cls.eviltwin_deauth_interval < 1:
            Color.pl('{!} {R}Error: Deauth interval must be at least 1 second{W}')
            raise RuntimeError('Invalid deauth interval')

        # Validate channel if specified
        if cls.eviltwin_channel is not None:
            if cls.eviltwin_channel < 1 or cls.eviltwin_channel > 165:
                Color.pl('{!} {R}Error: Invalid channel {O}%d{W}' % cls.eviltwin_channel)
                raise RuntimeError('Invalid channel for Evil Twin attack')

        # Validate template
        valid_templates = ['generic', 'tplink', 'netgear', 'linksys']
        if cls.eviltwin_template not in valid_templates:
            Color.pl('{!} {R}Error: Invalid template {O}%s{W}' % cls.eviltwin_template)
            Color.pl('{!} {O}Valid templates: {G}%s{W}' % ', '.join(valid_templates))
            raise RuntimeError('Invalid captive portal template')

        Color.pl('{+} {G}Evil Twin configuration validated{W}')
        Color.pl('{+} Found {G}%d{W} AP-capable interface(s)' % len(ap_interfaces))

    @classmethod
    def _validate_attack_monitor_config(cls):
        """Validate attack monitoring configuration settings."""
        from .tools.tshark import Tshark

        # Validate tshark is available
        if not Tshark.exists():
            Color.pl('{!} {R}Error: tshark not found{W}')
            Color.pl('{!} {O}Attack monitoring requires tshark for frame capture{W}')
            Color.pl('{!} {O}Install with:{W} {C}apt install tshark{W} or {C}yum install wireshark{W}')
            raise RuntimeError('tshark is required for attack monitoring')

        # Validate duration
        if cls.monitor_duration < 0:
            Color.pl('{!} {R}Error: Invalid monitoring duration {O}%d{W}' % cls.monitor_duration)
            raise ValueError('Monitoring duration must be 0 (infinite) or positive')

        # Validate channel
        if cls.monitor_channel is not None:
            if cls.monitor_channel < 1 or cls.monitor_channel > 165:
                Color.pl('{!} {R}Error: Invalid channel {O}%d{W}' % cls.monitor_channel)
                Color.pl('{!} {O}Valid channels: 1-14 (2.4GHz), 36-165 (5GHz){W}')
                raise ValueError('Invalid channel number')

        # Validate channel and hop are not both set
        if cls.monitor_channel and cls.monitor_hop:
            Color.pl('{!} {R}Error: Cannot specify both --monitor-channel and --monitor-hop{W}')
            raise ValueError('Cannot use both specific channel and channel hopping')

        # Validate log file path if specified
        if cls.monitor_log_file:
            import os
            log_dir = os.path.dirname(cls.monitor_log_file)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir)
                    Color.pl('{+} Created log directory: {G}%s{W}' % log_dir)
                except OSError as e:
                    Color.pl('{!} {R}Error: Cannot create log directory {O}%s{W}: %s' % (log_dir, str(e)))
                    raise ValueError('Invalid log file path')

        if cls.verbose > 0:
            Color.pl('{+} {G}Attack monitoring configuration validated{W}')

    @classmethod
    def _validate_wpasec_config(cls):
        """
        Validate wpa-sec configuration settings.

        Performs validation checks on wpa-sec configuration:
        - API key presence (required when wpa-sec is enabled)
        - API key format (minimum 8 characters, alphanumeric with hyphens/underscores)
        - API key character validation

        Raises:
            RuntimeError: If validation fails with descriptive error message

        Side Effects:
            - Displays error messages to user via Color.pl()
            - Provides helpful hints for fixing configuration issues

        Example:
            >>> Configuration.wpasec_enabled = True
            >>> Configuration.wpasec_api_key = "abc123"
            >>> Configuration._validate_wpasec_config()
            RuntimeError: Invalid wpa-sec API key: too short
        """
        import re

        # Validate API key format if provided
        if cls.wpasec_api_key:
            # API key should be alphanumeric and at least 8 characters
            if len(cls.wpasec_api_key) < 8:
                Color.pl('{!} {R}Error: wpa-sec API key must be at least 8 characters{W}')
                raise RuntimeError('Invalid wpa-sec API key: too short')

            # Check if API key contains only valid characters (alphanumeric and common special chars)
            if not re.match(r'^[a-zA-Z0-9_\-]+$', cls.wpasec_api_key):
                Color.pl('{!} {R}Error: wpa-sec API key contains invalid characters{W}')
                Color.pl('{!} {O}API key should only contain letters, numbers, hyphens, and underscores{W}')
                raise RuntimeError('Invalid wpa-sec API key format')
        else:
            # API key is required if wpa-sec is enabled
            Color.pl('{!} {R}Error: wpa-sec upload enabled but no API key provided{W}')
            Color.pl('{!} {O}Use {C}--wpasec-key{O} to specify your wpa-sec.stanev.org API key{W}')
            raise RuntimeError('wpa-sec API key required')

        # Validate URL format if custom URL provided
        if cls.wpasec_url:
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)

            if not url_pattern.match(cls.wpasec_url):
                Color.pl('{!} {R}Error: Invalid wpa-sec URL format: {O}%s{W}' % cls.wpasec_url)
                Color.pl('{!} {O}URL must start with http:// or https://{W}')
                raise RuntimeError('Invalid wpa-sec URL format')

        # Validate timeout value is positive integer
        if cls.wpasec_timeout:
            if not isinstance(cls.wpasec_timeout, int) or cls.wpasec_timeout <= 0:
                Color.pl('{!} {R}Error: wpa-sec timeout must be a positive integer{W}')
                raise RuntimeError('Invalid wpa-sec timeout value')

            if cls.wpasec_timeout < 10:
                Color.pl('{!} {O}Warning: wpa-sec timeout is very short ({G}%d{O} seconds){W}' % cls.wpasec_timeout)
                Color.pl('{!} {O}Uploads may fail due to insufficient time{W}')

        # Validate email format if provided
        if cls.wpasec_email:
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            if not email_pattern.match(cls.wpasec_email):
                Color.pl('{!} {R}Error: Invalid email format: {O}%s{W}' % cls.wpasec_email)
                raise RuntimeError('Invalid wpa-sec email format')

        if cls.verbose > 0:
            Color.pl('{+} {G}wpa-sec configuration validated{W}')

    @classmethod
    def parse_settings_args(cls, args):
        """Parses basic settings/configurations from arguments."""

        if args.random_mac or args.random_mac_vendor:
            if args.random_mac and args.random_mac_vendor:
                Color.pl('{!} {O}Warning: Cannot use both --random-mac and --random-mac-vendor')
                Color.pl('{+} {W}Falling back to {C}--random-mac{W} (full random) for better privacy')
                args.random_mac_vendor = False

            if args.random_mac:
                cls.random_mac = True
                cls.random_mac_vendor = False
                mode_str = "full random (maximum privacy)"
            else:
                cls.random_mac_vendor = True
                cls.random_mac = False
                mode_str = "vendor-preserved (better compatibility)"

            Color.pl('{+} {C}option:{W} using {G}random MAC address{W} ({C}%s{W}) when scanning & attacking' % mode_str)

        if args.channel:
            chn_arg_re = re.compile(r"^\d+((,\d+)|(-\d+,\d+))*(-\d+)?$")
            if not chn_arg_re.match(args.channel):
                raise ValueError("Invalid channel! The format must be 1,3-6,9")

            cls.target_channel = args.channel
            Color.pl('{+} {C}option:{W} scanning for targets on channel {G}%s{W}' % args.channel)

        if args.interface:
            cls.interface = args.interface
            Color.pl('{+} {C}option:{W} using wireless interface {G}%s{W}' % args.interface)

        if args.target_bssid:
            cls.target_bssid = args.target_bssid
            Color.pl('{+} {C}option:{W} targeting BSSID {G}%s{W}' % args.target_bssid)

        if args.all_bands:
            cls.all_bands = True
            Color.pl('{+} {C}option:{W} including both {G}2.4Ghz and 5Ghz networks{W} in scans')

        if args.two_ghz:
            cls.two_ghz = True
            Color.pl('{+} {C}option:{W} including {G}2.4Ghz networks{W} in scans')

        if args.five_ghz:
            cls.five_ghz = True
            Color.pl('{+} {C}option:{W} including {G}5Ghz networks{W} in scans')

        if args.infinite_mode:
            cls.infinite_mode = True
            Color.p('{+} {C}option:{W} ({G}infinite{W}) attack all neighbors forever')
            if not args.scan_time:
                Color.p(f'; {{O}}pillage time not selected{{W}}, using default {{G}}{cls.inf_wait_time:d}{{W}}s')
                args.scan_time = cls.inf_wait_time
            Color.pl('')

        if args.show_bssids:
            cls.show_bssids = True
            Color.pl('{+} {C}option:{W} showing {G}bssids{W} of targets during scan')

        if args.show_manufacturers is True:
            cls.show_manufacturers = True
            Color.pl('{+} {C}option:{W} showing {G}manufacturers{W} of targets during scan')

        if args.no_deauth:
            cls.no_deauth = True
            Color.pl('{+} {C}option:{W} will {R}not{W} {O}deauth{W} clients during scans or captures')

        if args.daemon is True:
            cls.daemon = True
            Color.pl('{+} {C}option:{W} will put interface back to managed mode')

        if args.num_deauths and args.num_deauths > 0:
            cls.num_deauths = args.num_deauths
            Color.pl(f'{{+}} {{C}}option:{{W}} send {{G}}{cls.num_deauths:d}{{W}} deauth packets when deauthing')

        if args.min_power and args.min_power > 0:
            cls.min_power = args.min_power
            Color.pl(f'{{+}} {{C}}option:{{W}} Minimum power {{G}}{cls.min_power:d}{{W}} for target to be shown')

        if args.skip_crack:
            cls.skip_crack = True
            Color.pl('{+} {C}option:{W} Skip cracking captured handshakes/pmkid {G}enabled{W}')

        if args.attack_max and args.attack_max > 0:
            cls.attack_max = args.attack_max
            Color.pl(f'{{+}} {{C}}option:{{W}} Attack first {{G}}{cls.attack_max:d}{{W}} targets from list')

        if args.target_essid:
            cls.target_essid = args.target_essid
            Color.pl('{+} {C}option:{W} targeting ESSID {G}%s{W}' % args.target_essid)

        if args.ignore_essids is not None:
            cls.ignore_essids = args.ignore_essids
            Color.pl('{+} {C}option: {O}ignoring ESSID(s): {R}%s{W}' %
                     ', '.join(args.ignore_essids))

        from .model.result import CrackResult
        cls.ignore_cracked = CrackResult.load_ignored_bssids(args.ignore_cracked)

        if args.ignore_cracked:
            if cls.ignore_cracked:
                Color.pl('{+} {C}option: {O}ignoring {R}%s{O} previously-cracked targets' % len(cls.ignore_cracked))

            else:
                Color.pl('{!} {R}Previously-cracked access points not found in %s' % cls.cracked_file)
                cls.ignore_cracked = False
        if args.clients_only:
            cls.clients_only = True
            Color.pl('{+} {C}option:{W} {O}ignoring targets that do not have associated clients')

        if args.scan_time:
            cls.scan_time = args.scan_time
            Color.pl(
                f'{{+}} {{C}}option:{{W}} ({{G}}pillage{{W}}) attack all targets after {{G}}{args.scan_time:d}{{W}}s')

        # TUI settings
        if hasattr(args, 'use_tui') and args.use_tui:
            cls.use_tui = True
            Color.pl('{+} {C}option:{W} using {G}interactive TUI mode{W}')
        elif hasattr(args, 'no_tui') and args.no_tui:
            cls.use_tui = False
            Color.pl('{+} {C}option:{W} using {G}classic text mode{W} (TUI disabled)')
        # else: use_tui remains False (classic mode is default)

        if args.verbose:
            cls.verbose = args.verbose
            Color.pl('{+} {C}option:{W} verbosity level {G}%d{W}' % args.verbose)

            # Update logger with verbosity level
            from .util.logger import Logger
            log_file = os.path.join(os.path.expanduser('~'), '.wifite', 'wifite.log') if args.verbose >= 2 else None
            Logger.initialize(log_file=log_file, verbose=args.verbose, enabled=True)

        if args.kill_conflicting_processes:
            cls.kill_conflicting_processes = True
            Color.pl('{+} {C}option:{W} kill conflicting processes {G}enabled{W}')

    @classmethod
    def parse_wep_args(cls, args):
        """Parses WEP-specific arguments"""
        if args.wep_filter:
            cls.wep_filter = args.wep_filter

        if args.wep_pps:
            cls.wep_pps = args.wep_pps
            Color.pl('{+} {C}option:{W} using {G}%d{W} packets/sec on WEP attacks' % args.wep_pps)

        if args.wep_timeout:
            cls.wep_timeout = args.wep_timeout
            Color.pl('{+} {C}option:{W} WEP attack timeout set to {G}%d seconds{W}' % args.wep_timeout)

        if args.require_fakeauth:
            cls.require_fakeauth = True
            Color.pl('{+} {C}option:{W} fake-authentication is {G}required{W} for WEP attacks')

        if args.wep_crack_at_ivs:
            cls.wep_crack_at_ivs = args.wep_crack_at_ivs
            Color.pl('{+} {C}option:{W} will start cracking WEP keys at {G}%d IVs{W}' % args.wep_crack_at_ivs)

        if args.wep_restart_stale_ivs:
            cls.wep_restart_stale_ivs = args.wep_restart_stale_ivs
            Color.pl('{+} {C}option:{W} will restart aireplay after {G}%d seconds{W} of no new IVs'
                     % args.wep_restart_stale_ivs)

        if args.wep_restart_aircrack:
            cls.wep_restart_aircrack = args.wep_restart_aircrack
            Color.pl('{+} {C}option:{W} will restart aircrack every {G}%d seconds{W}' % args.wep_restart_aircrack)

        if args.wep_keep_ivs:
            cls.wep_keep_ivs = args.wep_keep_ivs
            Color.pl('{+} {C}option:{W} keep .ivs files across multiple WEP attacks')

    @classmethod
    def parse_wpa_args(cls, args):
        """Parses WPA-specific arguments"""
        if args.wpa_filter:
            cls.wpa_filter = args.wpa_filter

        if hasattr(args, 'wpa3_filter') and args.wpa3_filter:
            cls.wpa3_filter = args.wpa3_filter

        if hasattr(args, 'owe_filter') and args.owe_filter:
            cls.owe_filter = args.owe_filter

        if args.wordlist:
            if not os.path.exists(args.wordlist):
                cls.wordlist = None
                Color.pl('{+} {C}option:{O} wordlist {R}%s{O} was not found, wifite will NOT attempt to crack '
                         'handshakes' % args.wordlist)
            elif os.path.isfile(args.wordlist):
                cls.wordlist = args.wordlist
                Color.pl('{+} {C}option:{W} using wordlist {G}%s{W} for cracking' % args.wordlist)
            elif os.path.isdir(args.wordlist):
                cls.wordlist = None
                Color.pl('{+} {C}option:{O} wordlist {R}%s{O} is a directory, not a file. Wifite will NOT attempt to '
                         'crack handshakes' % args.wordlist)

        if args.wpa_deauth_timeout:
            cls.wpa_deauth_timeout = args.wpa_deauth_timeout
            Color.pl('{+} {C}option:{W} will deauth WPA clients every {G}%d seconds{W}' % args.wpa_deauth_timeout)

        if args.wpa_attack_timeout:
            cls.wpa_attack_timeout = args.wpa_attack_timeout
            Color.pl(
                '{+} {C}option:{W} will stop WPA handshake capture after {G}%d seconds{W}' % args.wpa_attack_timeout)

        # WPA3-specific arguments
        if hasattr(args, 'wpa3_only') and args.wpa3_only:
            cls.wpa3_only = True
            Color.pl('{+} {C}option:{W} will attack {C}WPA3-SAE networks only{W}, skipping WPA2-only targets')

        if hasattr(args, 'wpa3_no_downgrade') and args.wpa3_no_downgrade:
            cls.wpa3_no_downgrade = True
            Color.pl('{+} {C}option:{W} will {O}disable transition mode downgrade{W} attacks, forcing SAE capture')

        if hasattr(args, 'wpa3_force_sae') and args.wpa3_force_sae:
            cls.wpa3_force_sae = True
            Color.pl('{+} {C}option:{W} will {O}skip WPA2 attacks{W} on transition mode, attacking SAE directly')

        if hasattr(args, 'wpa3_check_dragonblood') and args.wpa3_check_dragonblood:
            cls.wpa3_check_dragonblood = True
            Color.pl('{+} {C}option:{W} will {C}scan for Dragonblood vulnerabilities{W} only, skipping attacks')

        if hasattr(args, 'wpa3_attack_timeout') and args.wpa3_attack_timeout:
            cls.wpa3_attack_timeout = args.wpa3_attack_timeout
            Color.pl('{+} {C}option:{W} will stop WPA3-SAE attack after {G}%d seconds{W}' % args.wpa3_attack_timeout)
        else:
            # Default to wpa_attack_timeout if not specified
            cls.wpa3_attack_timeout = cls.wpa_attack_timeout

        if args.ignore_old_handshakes:
            cls.ignore_old_handshakes = True
            Color.pl('{+} {C}option:{W} will {O}ignore{W} existing handshakes (force capture)')

        if args.wpa_handshake_dir:
            cls.wpa_handshake_dir = args.wpa_handshake_dir
            Color.pl('{+} {C}option:{W} will store handshakes to {G}%s{W}' % args.wpa_handshake_dir)

        if args.wpa_strip_handshake:
            cls.wpa_strip_handshake = True
            Color.pl('{+} {C}option:{W} will {G}strip{W} non-handshake packets')

    @classmethod
    def parse_wps_args(cls, args):
        """Parses WPS-specific arguments"""
        if args.wps_filter:
            cls.wps_filter = args.wps_filter

        if args.wps_only:
            cls.wps_only = True
            cls.wps_filter = True  # Also only show WPS networks
            Color.pl('{+} {C}option:{W} will *only* attack WPS networks with '
                     '{G}WPS attacks{W} (avoids handshake and PMKID)')

        if args.no_wps:
            # No WPS attacks at all
            cls.no_wps = args.no_wps
            cls.wps_pixie = False
            cls.wps_no_nullpin = True
            cls.wps_pin = False
            Color.pl('{+} {C}option:{W} will {O}never{W} use {C}WPS attacks{W} (Pixie-Dust/PIN) on targets')

        elif args.wps_pixie:
            # WPS Pixie-Dust only
            cls.no_wps = False  # Explicitly ensure WPS attacks are enabled
            cls.wps_pixie = True
            cls.wps_no_nullpin = True
            cls.wps_pin = False
            Color.pl('{+} {C}option:{W} will {G}only{W} use {C}WPS Pixie-Dust attack{W} (no {O}PIN{W}) on targets')

        elif args.wps_no_nullpin:
            # WPS NULL PIN only
            cls.no_wps = False  # Explicitly ensure WPS attacks are enabled
            cls.wps_pixie = True
            cls.wps_no_nullpin = False
            cls.wps_pin = True
            Color.pl('{+} {C}option:{W} will {G}not{W} use {C}WPS NULL PIN attack{W} (no {O}PIN{W}) on targets')

        elif args.wps_no_pixie:
            # WPS PIN only
            cls.no_wps = False  # Explicitly ensure WPS attacks are enabled
            cls.wps_pixie = False
            cls.wps_no_nullpin = True
            cls.wps_pin = True
            Color.pl('{+} {C}option:{W} will {G}only{W} use {C}WPS PIN attack{W} (no {O}Pixie-Dust{W}) on targets')

        if args.use_bully:
            from .tools.bully import Bully
            if not Bully.exists():
                Color.pl('{!} {R}Bully not found. Defaulting to {O}reaver{W}')
                cls.use_bully = False
            else:
                cls.use_bully = args.use_bully
                Color.pl('{+} {C}option:{W} use {C}bully{W} instead of {C}reaver{W} for WPS Attacks')

        if args.use_reaver:
            from .tools.reaver import Reaver
            if not Reaver.exists():
                Color.pl('{!} {R}Reaver not found. Defaulting to {O}bully{W}')
                cls.use_reaver = False
            else:
                cls.use_reaver = args.use_reaver
                Color.pl('{+} {C}option:{W} use {C}reaver{W} instead of {C}bully{W} for WPS Attacks')

        if args.wps_pixie_timeout:
            cls.wps_pixie_timeout = args.wps_pixie_timeout
            Color.pl(
                '{+} {C}option:{W} WPS pixie-dust attack will fail after {O}%d seconds{W}' % args.wps_pixie_timeout)

        if args.wps_fail_threshold:
            cls.wps_fail_threshold = args.wps_fail_threshold
            Color.pl('{+} {C}option:{W} will stop WPS attack after {O}%d failures{W}' % args.wps_fail_threshold)

        if args.wps_timeout_threshold:
            cls.wps_timeout_threshold = args.wps_timeout_threshold
            Color.pl('{+} {C}option:{W} will stop WPS attack after {O}%d timeouts{W}' % args.wps_timeout_threshold)

        if args.wps_ignore_lock:
            cls.wps_ignore_lock = True
            Color.pl('{+} {C}option:{W} will {O}ignore{W} WPS lock-outs')

    @classmethod
    def parse_pmkid_args(cls, args):
        if args.use_pmkid_only:
            cls.use_pmkid_only = True
            Color.pl('{+} {C}option:{W} will ONLY use {C}PMKID{W} attack on WPA networks')

        if args.pmkid_timeout:
            cls.pmkid_timeout = args.pmkid_timeout
            Color.pl('{+} {C}option:{W} will wait {G}%d seconds{W} during {C}PMKID{W} capture' % args.pmkid_timeout)

        if args.dont_use_pmkid:
            cls.dont_use_pmkid = True
            Color.pl('{+} {C}option:{W} will NOT use {C}PMKID{W} attack on WPA networks')

        # Passive PMKID capture arguments
        if args.pmkid_passive:
            cls.pmkid_passive = True
            Color.pl('{+} {C}option:{W} {G}passive PMKID capture mode{W} enabled')

        if args.pmkid_passive_duration:
            cls.pmkid_passive_duration = args.pmkid_passive_duration
            Color.pl('{+} {C}option:{W} passive capture duration: {G}%d seconds{W}' % args.pmkid_passive_duration)

        if args.pmkid_passive_interval:
            cls.pmkid_passive_interval = args.pmkid_passive_interval
            Color.pl('{+} {C}option:{W} passive capture extraction interval: {G}%d seconds{W}' % args.pmkid_passive_interval)

    @classmethod
    def parse_eviltwin_args(cls, args):
        """Parses Evil Twin-specific arguments"""
        if args.use_eviltwin:
            cls.use_eviltwin = True
            Color.pl('{+} {C}option:{W} using {G}Evil Twin attacks{W} against all targets')

            # Display interface capabilities info
            cls._display_eviltwin_interface_info()

        if hasattr(args, 'eviltwin_deauth_iface') and args.eviltwin_deauth_iface:
            cls.eviltwin_deauth_iface = args.eviltwin_deauth_iface
            Color.pl('{+} {C}option:{W} Evil Twin deauth interface: {G}%s{W}' % args.eviltwin_deauth_iface)

        if hasattr(args, 'eviltwin_fakeap_iface') and args.eviltwin_fakeap_iface:
            cls.eviltwin_fakeap_iface = args.eviltwin_fakeap_iface
            Color.pl('{+} {C}option:{W} Evil Twin fake AP interface: {G}%s{W}' % args.eviltwin_fakeap_iface)

        if hasattr(args, 'eviltwin_port') and args.eviltwin_port:
            cls.eviltwin_port = args.eviltwin_port
            Color.pl('{+} {C}option:{W} Evil Twin captive portal port: {G}%d{W}' % args.eviltwin_port)

        if hasattr(args, 'eviltwin_deauth_interval') and args.eviltwin_deauth_interval:
            cls.eviltwin_deauth_interval = args.eviltwin_deauth_interval
            Color.pl('{+} {C}option:{W} Evil Twin deauth interval: {G}%d seconds{W}' % args.eviltwin_deauth_interval)

        if hasattr(args, 'eviltwin_template') and args.eviltwin_template:
            cls.eviltwin_template = args.eviltwin_template
            Color.pl('{+} {C}option:{W} Evil Twin portal template: {G}%s{W}' % args.eviltwin_template)

        if hasattr(args, 'eviltwin_channel') and args.eviltwin_channel:
            cls.eviltwin_channel = args.eviltwin_channel
            Color.pl('{+} {C}option:{W} Evil Twin channel override: {G}%d{W}' % args.eviltwin_channel)

        if hasattr(args, 'eviltwin_no_validate') and args.eviltwin_no_validate:
            cls.eviltwin_validate_credentials = False
            Color.pl('{+} {C}option:{W} Evil Twin credential validation: {O}disabled{W}')

    @classmethod
    def _display_eviltwin_interface_info(cls):
        """Display information about available interfaces for Evil Twin."""
        try:
            # Only display interface info in verbose mode to avoid blocking
            if cls.verbose < 1:
                return

            from .util.interface_manager import InterfaceManager

            # Get AP-capable interfaces
            ap_interfaces = InterfaceManager.get_ap_capable_interfaces()

            if ap_interfaces:
                Color.pl('{+} Found {G}%d{W} AP-capable interface(s):' % len(ap_interfaces))
                for caps in ap_interfaces:
                    info_parts = [caps.interface]
                    if caps.driver:
                        info_parts.append(f'driver: {caps.driver}')
                    if caps.chipset:
                        info_parts.append(f'chipset: {caps.chipset}')
                    Color.pl('{+}   {G}%s{W}' % ', '.join(info_parts))
            else:
                Color.pl('{!} {O}Warning: No AP-capable interfaces detected{W}')
                Color.pl('{!} {O}Evil Twin attack may not work without AP mode support{W}')

        except Exception as e:
            # Don't fail if we can't detect interfaces, just warn
            if cls.verbose > 0:
                Color.pl('{!} {O}Warning: Could not detect interface capabilities: %s{W}' % str(e))

    @classmethod
    def parse_attack_monitor_args(cls, args):
        """Parse wireless attack monitoring-specific arguments"""
        if hasattr(args, 'monitor_attacks') and args.monitor_attacks:
            cls.monitor_attacks = True
            Color.pl('{+} {C}option:{W} {G}wireless attack monitoring mode{W} enabled')

        if hasattr(args, 'monitor_duration') and args.monitor_duration:
            cls.monitor_duration = args.monitor_duration
            if args.monitor_duration > 0:
                Color.pl('{+} {C}option:{W} monitoring duration: {G}%d seconds{W}' % args.monitor_duration)
            else:
                Color.pl('{+} {C}option:{W} monitoring duration: {G}infinite{W}')

        if hasattr(args, 'monitor_log_file') and args.monitor_log_file:
            cls.monitor_log_file = args.monitor_log_file
            Color.pl('{+} {C}option:{W} attack log file: {G}%s{W}' % args.monitor_log_file)

        if hasattr(args, 'monitor_channel') and args.monitor_channel:
            cls.monitor_channel = args.monitor_channel
            # Validate channel number
            if cls.monitor_channel < 1 or cls.monitor_channel > 165:
                Color.pl('{!} {R}Error: Invalid channel {O}%d{W}' % cls.monitor_channel)
                raise ValueError('Invalid channel number for attack monitoring')
            Color.pl('{+} {C}option:{W} monitoring channel: {G}%d{W}' % args.monitor_channel)

        if hasattr(args, 'monitor_hop') and args.monitor_hop:
            cls.monitor_hop = True
            Color.pl('{+} {C}option:{W} channel hopping {G}enabled{W} (all 2.4GHz channels)')
            # Validate that both channel and hop are not set
            if cls.monitor_channel:
                Color.pl('{!} {R}Error: Cannot specify both --monitor-channel and --monitor-hop{W}')
                raise ValueError('Cannot use both specific channel and channel hopping')

    @classmethod
    def parse_dual_interface_args(cls, args):
        """Parses dual interface-specific arguments"""
        # Check if dual interface mode is explicitly enabled
        if hasattr(args, 'dual_interface') and args.dual_interface:
            cls.dual_interface_enabled = True
            Color.pl('{+} {C}option:{W} dual interface mode {G}enabled{W}')

        # Check if dual interface mode is explicitly disabled
        if hasattr(args, 'no_dual_interface') and args.no_dual_interface:
            cls.dual_interface_enabled = False
            cls.prefer_dual_interface = False
            Color.pl('{+} {C}option:{W} dual interface mode {O}disabled{W} (single interface mode)')

        # Manual primary interface selection
        if hasattr(args, 'interface_primary') and args.interface_primary:
            cls.interface_primary = args.interface_primary
            Color.pl('{+} {C}option:{W} primary interface: {G}%s{W}' % args.interface_primary)
            # If primary is specified, enable dual interface mode
            if not hasattr(args, 'no_dual_interface') or not args.no_dual_interface:
                cls.dual_interface_enabled = True

        # Manual secondary interface selection
        if hasattr(args, 'interface_secondary') and args.interface_secondary:
            cls.interface_secondary = args.interface_secondary
            Color.pl('{+} {C}option:{W} secondary interface: {G}%s{W}' % args.interface_secondary)
            # If secondary is specified, enable dual interface mode
            if not hasattr(args, 'no_dual_interface') or not args.no_dual_interface:
                cls.dual_interface_enabled = True

        # Validate manual interface selection
        if cls.interface_primary and cls.interface_secondary:
            if cls.interface_primary == cls.interface_secondary:
                Color.pl('{!} {R}Error: Primary and secondary interfaces must be different{W}')
                raise ValueError('Primary and secondary interfaces cannot be the same')

        # Auto-assign setting (default is True)
        if hasattr(args, 'no_auto_assign') and args.no_auto_assign:
            cls.auto_assign_interfaces = False
            Color.pl('{+} {C}option:{W} automatic interface assignment {O}disabled{W}')

        # hcxdump mode for WPA capture (single or dual interface)
        if hasattr(args, 'use_hcxdump') and args.use_hcxdump:
            cls.use_hcxdump = True
            Color.pl('{+} {C}option:{W} using {G}hcxdumptool{W} for WPA handshake capture')

    @classmethod
    def parse_wpasec_args(cls, args):
        """
        Parse wpa-sec upload-specific command-line arguments.

        Extracts and sets wpa-sec configuration from parsed arguments including:
        - API key (with masking for security)
        - Auto-upload mode
        - Custom server URL
        - Connection timeout
        - Notification email
        - File removal after upload

        Args:0
            args: Parsed command-line arguments object from argparse

        Side Effects:
            - Sets class variables for wpa-sec configuration
            - Displays configuration messages to user via Color.pl()
            - Automatically enables wpasec_enabled if API key is provided

        Example:
            >>> Configuration.parse_wpasec_args(parsed_args)
            {+} option: wpa-sec API key: abc1****
            {+} option: wpa-sec automatic upload enabled (no prompts)
        """
        if hasattr(args, 'wpasec_enabled') and args.wpasec_enabled:
            cls.wpasec_enabled = True
            Color.pl('{+} {C}option:{W} wpa-sec upload functionality {G}enabled{W}')

        if hasattr(args, 'wpasec_api_key') and args.wpasec_api_key:
            cls.wpasec_api_key = args.wpasec_api_key
            # Mask the API key in output for security
            masked_key = args.wpasec_api_key[:4] + '*' * (len(args.wpasec_api_key) - 4) if len(args.wpasec_api_key) > 4 else '****'
            Color.pl('{+} {C}option:{W} wpa-sec API key: {G}%s{W}' % masked_key)
            # Enable wpa-sec if API key is provided
            cls.wpasec_enabled = True

        if hasattr(args, 'wpasec_auto_upload') and args.wpasec_auto_upload:
            cls.wpasec_auto_upload = True
            Color.pl('{+} {C}option:{W} wpa-sec {G}automatic upload{W} enabled (no prompts)')

        if hasattr(args, 'wpasec_url') and args.wpasec_url:
            cls.wpasec_url = args.wpasec_url
            Color.pl('{+} {C}option:{W} wpa-sec custom URL: {G}%s{W}' % args.wpasec_url)

        if hasattr(args, 'wpasec_timeout') and args.wpasec_timeout:
            cls.wpasec_timeout = args.wpasec_timeout
            Color.pl('{+} {C}option:{W} wpa-sec upload timeout: {G}%d seconds{W}' % args.wpasec_timeout)

        if hasattr(args, 'wpasec_email') and args.wpasec_email:
            cls.wpasec_email = args.wpasec_email
            Color.pl('{+} {C}option:{W} wpa-sec notification email: {G}%s{W}' % args.wpasec_email)

        if hasattr(args, 'wpasec_remove_after_upload') and args.wpasec_remove_after_upload:
            cls.wpasec_remove_after_upload = True
            Color.pl('{+} {C}option:{W} wpa-sec {O}remove capture files{W} after successful upload')

    @classmethod
    def parse_tui_args(cls, args):
        """Parse TUI-related arguments"""
        if args.use_tui:
            cls.use_tui = True
            Color.pl('{+} {C}option:{W} using {G}interactive TUI mode{W}')
        elif args.no_tui:
            cls.use_tui = False
            Color.pl('{+} {C}option:{W} using {G}classic text mode{W}')
        # If neither flag is set, use_tui remains False (classic mode is default)

    @classmethod
    def parse_encryption(cls):
        """Adjusts encryption filter (WEP and/or WPA and/or WPS)"""
        cls.encryption_filter = []
        if cls.wep_filter:
            cls.encryption_filter.append('WEP')
        if cls.wpa_filter: # WPA/WPA2
            cls.encryption_filter.append('WPA') 
        if cls.wpa3_filter or cls.wpa3_only:
            cls.encryption_filter.append('WPA3')
        if cls.owe_filter:
            cls.encryption_filter.append('OWE')
        if cls.wps_filter: # WPS can be on WPA/WPA2
            cls.encryption_filter.append('WPS')

        cls.encryption_filter = sorted(list(set(cls.encryption_filter))) # Remove duplicates and sort

        if not cls.encryption_filter:
            # Default to scan all known types if no specific filter is chosen
            cls.encryption_filter = ['WEP', 'WPA', 'WPA3', 'OWE', 'WPS']
            Color.pl('{+} {C}option:{W} targeting {G}all known encryption types{W} by default')
        elif len(cls.encryption_filter) == 5 and 'WPS' in cls.encryption_filter and 'OWE' in cls.encryption_filter: # Approximation for "all"
             Color.pl('{+} {C}option:{W} targeting {G}all specified encrypted networks{W}')
        else:
            Color.pl('{+} {C}option:{W} targeting {G}%s-encrypted{W} networks' % '/'.join(cls.encryption_filter))

    @classmethod
    def parse_wep_attacks(cls):
        """Parses and sets WEP-specific args (-chopchop, -fragment, etc)"""
        cls.wep_attacks = []
        from sys import argv
        seen = set()
        for arg in argv:
            if arg in seen:
                continue
            seen.add(arg)
            if arg == '-arpreplay':
                cls.wep_attacks.append('replay')
            elif arg == '-caffelatte':
                cls.wep_attacks.append('caffelatte')
            elif arg == '-chopchop':
                cls.wep_attacks.append('chopchop')
            elif arg == '-fragment':
                cls.wep_attacks.append('fragment')
            elif arg == '-hirte':
                cls.wep_attacks.append('hirte')
            elif arg == '-p0841':
                cls.wep_attacks.append('p0841')
        if not cls.wep_attacks:
            # Use all attacks
            cls.wep_attacks = ['replay',
                               'fragment',
                               'chopchop',
                               'caffelatte',
                               'p0841',
                               'hirte']

        elif len(cls.wep_attacks) > 0:
            Color.pl('{+} {C}option:{W} using {G}%s{W} WEP attacks'
                     % '{W}, {G}'.join(cls.wep_attacks))

    @classmethod
    def temp(cls, subfile=''):
        """ Creates and/or returns the temporary directory """
        if cls.temp_dir is None:
            cls.temp_dir = cls.create_temp()
        return cls.temp_dir + subfile

    @staticmethod
    def create_temp():
        """ Creates and returns a temporary directory """
        from tempfile import mkdtemp
        tmp = mkdtemp(prefix='wifite')
        if not tmp.endswith(os.sep):
            tmp += os.sep
        return tmp

    @classmethod
    def delete_temp(cls):
        """ Remove temp files and folder """
        if cls.temp_dir is None:
            return
        if os.path.exists(cls.temp_dir):
            for f in os.listdir(cls.temp_dir):
                try:
                    file_path = os.path.join(cls.temp_dir, f)
                    os.remove(file_path)
                except (OSError, IOError):
                    pass  # Ignore errors during cleanup
            try:
                os.rmdir(cls.temp_dir)
            except (OSError, IOError):
                pass  # Ignore errors during cleanup

    @classmethod
    def cleanup_memory(cls):
        """ Periodic memory cleanup during long operations """
        # Clear command cache periodically
        if hasattr(cls, 'existing_commands') and len(cls.existing_commands) > 100:
            # Keep only the most recently used commands
            cls.existing_commands = dict(list(cls.existing_commands.items())[-50:])

        # Clean up processes and file descriptors
        from .util.process import ProcessManager, Process
        ProcessManager().cleanup_all()
        Process.cleanup_zombies()

        # Force garbage collection
        import gc
        gc.collect()

    @classmethod
    def exit_gracefully(cls):
        """ Deletes temp and exist with the given code """
        code = 0
        cls.delete_temp()
        Macchanger.reset_if_changed()

        # Clean up managed interfaces (Task 10.4)
        try:
            from .util.interface_manager import InterfaceManager
            from .util.logger import log_info, log_debug

            # Check if we have an interface manager instance to clean up
            if hasattr(cls, 'interface_manager') and cls.interface_manager is not None:
                log_info('Config', 'Cleaning up managed interfaces')
                restored = cls.interface_manager.cleanup_all()
                log_debug('Config', f'Restored {restored} interface(s)')
        except Exception as e:
            from .util.logger import log_error
            log_error('Config', f'Error during interface cleanup: {e}', e)

        from .tools.airmon import Airmon
        if cls.interface is not None and Airmon.base_interface is not None:
            if not cls.daemon:
                Color.pl('{!} {O}Note:{W} Leaving interface in Monitor Mode!')
                if Airmon.isdeprecated:
                    Color.pl('{!} To disable Monitor Mode when finished: {C}iwconfig %s mode managed{W}' % cls.interface)
                else:
                    Color.pl('{!} To disable Monitor Mode when finished: {C}airmon-ng stop %s{W}' % cls.interface)
            else:
                # Stop monitor mode
                Airmon.stop(cls.interface)
                # Bring original interface back up
                Airmon.put_interface_up(Airmon.base_interface)

        if Airmon.killed_network_manager:
            Color.pl('{!} You can restart NetworkManager when finished ({C}service NetworkManager start{W})')
            # Airmon.start_network_manager()

        exit(code)

    @classmethod
    def dump(cls):
        """ (Colorful) string representation of the configuration """
        from .util.color import Color

        max_len = 20
        for key in list(cls.__dict__.keys()):
            max_len = max(max_len, len(key))

        result = Color.s('{W}%s  Value{W}\n' % 'cls Key'.ljust(max_len))
        result += Color.s('{W}%s------------------{W}\n' % ('-' * max_len))

        for (key, val) in sorted(cls.__dict__.items()):
            if key.startswith('__') or type(val) in [classmethod, staticmethod] or val is None:
                continue
            result += Color.s('{G}%s {W} {C}%s{W}\n' % (key.ljust(max_len), val))
        return result


if __name__ == '__main__':
    Configuration.initialize(False)
    print((Configuration.dump()))
