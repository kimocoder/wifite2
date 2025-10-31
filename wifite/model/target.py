#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..util.color import Color
from ..config import Configuration
import re

class WPSState:
    NONE, UNLOCKED, LOCKED, UNKNOWN = list(range(4))


class ArchivedTarget(object):
    """
        Holds information between scans from a previously found target
    """

    def __init__(self, target):
        self.bssid = target.bssid
        self.channel = target.channel
        self.decloaked = target.decloaked
        self.attacked = target.attacked
        self.essid = target.essid
        self.essid_known = target.essid_known
        self.essid_len = target.essid_len

    def transfer_info(self, other):
        """
            Helper function to transfer relevant fields into another Target or ArchivedTarget
        """
        other.attacked = self.attacked

        if self.essid_known and other.essid_known:
            other.decloaked = self.decloaked

        if not other.essid_known:
                other.decloaked = self.decloaked
                other.essid = self.essid
                other.essid_known = self.essid_known
                other.essid_len = self.essid_len

    def __eq__(self, other):
        # Check if the other class type is either ArchivedTarget or Target
        return isinstance(other, (self.__class__, Target)) and self.bssid == other.bssid

class Target(object):
    """
        Holds details for a 'Target' aka Access Point (e.g. router).
    """

    def __init__(self, fields):
        """
            Initializes & stores target info based on fields.
            Args:
                Fields - List of strings
                INDEX KEY             EXAMPLE
                    0 BSSID           (00:1D:D5:9B:11:00)
                    1 First time seen (2015-05-27 19:28:43)
                    2 Last time seen  (2015-05-27 19:28:46)
                    3 channel         (6)
                    4 Speed           (54)
                    5 Privacy         (WPA2 OWE)
                    6 Cipher          (CCMP TKIP)
                    7 Authentication  (PSK SAE)
                    8 Power           (-62)
                    9 beacons         (2)
                    10 # IV           (0)
                    11 LAN IP         (0.  0.  0.  0)
                    12 ID-length      (9)
                    13 ESSID          (HOME-ABCD)
                    14 Key            ()
        """
        self.manufacturer = None
        self.wps = WPSState.NONE
        self.bssid = fields[0].strip()
        try:
            self.channel = int(fields[3].strip())
        except (ValueError, IndexError):
            self.channel = -1
        self.encryption = fields[5].strip() # Contains encryption type(s) like "WPA2 WPA3 OWE"
        self.authentication = fields[7].strip() # Contains auth type(s) like "PSK SAE MGT"

        # Determine primary encryption and auth
        # Note: SAE (Simultaneous Authentication of Equals) is the authentication method for WPA3
        # If we see SAE in authentication, it's WPA3 even if encryption field doesn't say "WPA3"
        if 'WPA3' in self.encryption or 'SAE' in self.authentication:
            self.primary_encryption = 'WPA3'
        elif 'WPA2' in self.encryption:
            self.primary_encryption = 'WPA2'
        elif 'WPA' in self.encryption: # Handles cases where only "WPA" is present or if no other WPAx is found
            self.primary_encryption = 'WPA'
        elif 'WEP' in self.encryption:
            self.primary_encryption = 'WEP'
        elif 'OWE' in self.encryption: # Opportunistic Wireless Encryption
            self.primary_encryption = 'OWE'
        elif len(self.encryption) == 0: # Default to WPA if not specified, as per old logic
            self.primary_encryption = 'WPA'
        else: # Fallback for unknown types
            self.primary_encryption = self.encryption.split(' ')[0]


        if 'SAE' in self.authentication:
            self.primary_authentication = 'SAE'
        elif 'PSK' in self.authentication:
            self.primary_authentication = 'PSK'
        elif 'MGT' in self.authentication: # Enterprise
            self.primary_authentication = 'MGT'
        elif 'OWE' in self.authentication: # OWE uses its own auth mechanism
            self.primary_authentication = 'OWE'
        else:
            self.primary_authentication = self.authentication.split(' ')[0] if self.authentication else ''


        self.power = int(fields[8].strip())
        if self.power < 0:
            self.power += 100
        self.max_power = self.power

        self.beacons = int(fields[9].strip())
        self.ivs = int(fields[10].strip())

        self.essid_known = True
        self.essid_len = int(fields[12].strip())
        self.essid = fields[13]
        if self.essid == '\\x00' * self.essid_len or \
                self.essid == 'x00' * self.essid_len or \
                self.essid.strip() == '':
            # Don't display '\x00...' for hidden ESSIDs
            self.essid = None  # '(%s)' % self.bssid
            self.essid_known = False

        # self.wps = WPSState.UNKNOWN

        # Will be set to true once this target will be attacked
        # Needed to count targets in infinite attack mode
        self.attacked = False

        self.decloaked = False  # If ESSID was hidden but we decloaked it.

        self.clients = []

        # Store full encryption and authentication strings for detailed info if needed
        self.full_encryption_string = self.encryption
        self.full_authentication_string = self.authentication
        # For compatibility with existing logic that expects a single string:
        self.encryption = self.primary_encryption # Overwrite with primary for now
        self.authentication = self.primary_authentication # Overwrite with primary for now
        
        # WPA3 information (will be populated by scanner)
        self.wpa3_info = None
        
        self.validate()

    def __eq__(self, other):
        # Check if the other class type is either ArchivedTarget or Target
        return isinstance(other, (self.__class__, ArchivedTarget)) and self.bssid == other.bssid

    def transfer_info(self, other):
        """
            Helper function to transfer relevant fields into another Target or ArchivedTarget
        """
        other.wps = self.wps
        other.attacked = self.attacked

        if self.essid_known:
            if other.essid_known:
                other.decloaked = self.decloaked

            if not other.essid_known:
                other.decloaked = self.decloaked
                other.essid = self.essid
                other.essid_known = self.essid_known
                other.essid_len = self.essid_len

        # Transfer new fields as well
        if hasattr(self, 'primary_encryption'):
            other.primary_encryption = self.primary_encryption
            other.full_encryption_string = self.full_encryption_string
        if hasattr(self, 'primary_authentication'):
            other.primary_authentication = self.primary_authentication
            other.full_authentication_string = self.full_authentication_string
        if hasattr(self, 'wpa3_info'):
            other.wpa3_info = self.wpa3_info

    @property
    def is_wpa3(self):
        """Check if target supports WPA3."""
        if self.wpa3_info is None:
            return False
        return self.wpa3_info.has_wpa3
    
    @property
    def is_transition(self):
        """Check if target is in WPA3 transition mode (supports both WPA2 and WPA3)."""
        if self.wpa3_info is None:
            return False
        return self.wpa3_info.is_transition
    
    @property
    def pmf_status(self):
        """Get PMF (Protected Management Frames) status."""
        if self.wpa3_info is None:
            return 'disabled'
        return self.wpa3_info.pmf_status
    
    @property
    def is_dragonblood_vulnerable(self):
        """Check if target is vulnerable to Dragonblood attacks."""
        if self.wpa3_info is None:
            return False
        return self.wpa3_info.dragonblood_vulnerable

    def validate(self):
        """ Checks that the target is valid. """
        if self.channel == -1:
            pass

        # Filter broadcast/multicast BSSIDs, see https://github.com/derv82/wifite2/issues/32
        bssid_broadcast = re.compile(r'^(ff:ff:ff:ff:ff:ff|00:00:00:00:00:00)$', re.IGNORECASE)
        if bssid_broadcast.match(self.bssid):
            raise Exception(f'Ignoring target with Broadcast BSSID ({self.bssid})')

        bssid_multicast = re.compile(r'^(01:00:5e|01:80:c2|33:33)', re.IGNORECASE)
        if bssid_multicast.match(self.bssid):
            raise Exception(f'Ignoring target with Multicast BSSID ({self.bssid})')

    def to_str(self, show_bssid=False, show_manufacturer=False):
        # sourcery no-metrics
        """
            *Colored* string representation of this Target.
            Specifically formatted for the 'scanning' table view.
        """

        max_essid_len = 24
        essid = self.essid if self.essid_known else f'({self.bssid})'
        # Trim ESSID (router name) if needed
        if len(essid) > max_essid_len:
            essid = f'{essid[:max_essid_len - 3]}...'
        else:
            essid = essid.rjust(max_essid_len)

        if self.essid_known:
            # Known ESSID
            essid = Color.s('{C}%s' % essid)
        else:
            # Unknown ESSID
            essid = Color.s('{O}%s' % essid)

        # if self.power < self.max_power:
        #     var = self.max_power

        # Add a '*' if we decloaked the ESSID
        decloaked_char = '*' if self.decloaked else ' '
        essid += Color.s('{P}%s' % decloaked_char)

        bssid = Color.s('{O}%s  ' % self.bssid) if show_bssid else ''
        if show_manufacturer:
            oui = ''.join(self.bssid.split(':')[:3])
            self.manufacturer = Configuration.manufacturers.get(oui, "")

            max_oui_len = 27
            manufacturer = Color.s('{W}%s  ' % self.manufacturer)
            # Trim manufacturer name if needed
            if len(manufacturer) > max_oui_len:
                manufacturer = f'{manufacturer[:max_oui_len - 3]}...'
            else:
                manufacturer = manufacturer.rjust(max_oui_len)
        else:
            manufacturer = ''

        channel_color = '{C}' if int(self.channel) > 14 else '{G}'
        channel = Color.s(f'{channel_color}{str(self.channel).rjust(3)}')

        # Use primary_encryption and primary_authentication for display
        # Check for WPA3 transition mode
        if self.is_transition:
            # Show "W23" for transition mode (WPA2/WPA3)
            display_encryption = Color.s('{P}W23') # Purple for WPA3 transition
            auth_suffix = ''
            # Add PMF indicator for transition mode
            if self.pmf_status == 'required':
                auth_suffix = Color.s('{P}+') # PMF required
            elif self.pmf_status == 'optional':
                auth_suffix = Color.s('{O}~') # PMF optional
        else:
            display_encryption = self.primary_encryption.rjust(4) # Adjusted rjust for WPA3
            auth_suffix = ''
            if self.primary_encryption == 'WPA3':
                display_encryption = Color.s('{P}%s' % display_encryption) # Purple for WPA3
                # Don't add -S suffix since WPA3 already implies SAE
                # Just add PMF indicator if present
                if self.pmf_status == 'required':
                    auth_suffix = Color.s('{P}+') # PMF required
                elif self.pmf_status == 'optional':
                    auth_suffix = Color.s('{O}~') # PMF optional
                # Only show -E for enterprise WPA3
                if self.primary_authentication == 'MGT':
                    auth_suffix = Color.s('{R}-E') + auth_suffix # Red for Enterprise
            elif self.primary_encryption == 'WPA2':
                display_encryption = Color.s('{O}%s' % display_encryption) # Orange for WPA2
                if self.primary_authentication == 'PSK':
                    auth_suffix = Color.s('{O}-P')
                elif self.primary_authentication == 'MGT':
                    auth_suffix = Color.s('{R}-E')
            elif self.primary_encryption == 'WPA':
                display_encryption = Color.s('{O}%s' % display_encryption) # Orange for WPA
                if self.primary_authentication == 'PSK':
                    auth_suffix = Color.s('{O}-P')
                elif self.primary_authentication == 'MGT':
                    auth_suffix = Color.s('{R}-E')
            elif self.primary_encryption == 'WEP':
                display_encryption = Color.s('{G}%s' % display_encryption) # Green for WEP
            elif self.primary_encryption == 'OWE':
                display_encryption = Color.s('{B}%s' % display_encryption) # Blue for OWE
            else:
                display_encryption = Color.s('{W}%s' % display_encryption) # White for others

        # Calculate padding for ENCR column based on its content length
        # Max length of ENCR (e.g. WPA2-P or W23+) is now variable
        # Pad with spaces to ensure alignment
        base_len = 3 if self.is_transition else len(self.primary_encryption)
        suffix_len = len(auth_suffix.replace(Color.s('{P}'), '').replace(Color.s('{O}'), '').replace(Color.s('{R}'), '').replace(Color.s('{W}'), ''))
        encryption_padding = " " * max(0, 7 - base_len - suffix_len)
        encryption_display_string = f"{display_encryption}{auth_suffix}{encryption_padding}"

        power = f'{str(self.power).rjust(3)}db'
        if self.power > 50:
            color = 'G'
        elif self.power > 35:
            color = 'O'
        else:
            color = 'R'
        power = Color.s('{%s}%s' % (color, power))

        if self.wps == WPSState.UNLOCKED:
            wps = Color.s('{G} yes')
        elif self.wps == WPSState.NONE:
            wps = Color.s('{O}  no')
        elif self.wps == WPSState.LOCKED:
            wps = Color.s('{R}lock')
        elif self.wps == WPSState.UNKNOWN:
            wps = Color.s('{O} n/a')
        else:
            wps = ' ERR'

        clients = '       '
        if len(self.clients) > 0:
            clients = Color.s('{G}  ' + str(len(self.clients)))

        result = f'{essid}  {bssid}{manufacturer}{channel}  {encryption_display_string}   {power}  {wps}  {clients}'

        result += Color.s('{W}')
        return result


if __name__ == '__main__':
    fields = 'AA:BB:CC:DD:EE:FF,2015-05-27 19:28:44,2015-05-27 19:28:46,1,54,WPA2,CCMP ' \
             'TKIP,PSK,-58,2,0,0.0.0.0,9,HOME-ABCD,'.split(',')
    t = Target(fields)
    t.clients.append('asdf')
    t.clients.append('asdf')
    print((t.to_str()))
