#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from .tshark import Tshark
from .wash import Wash
from ..util.process import Process
from ..config import Configuration
from ..model.target import Target, WPSState
from ..model.client import Client

import os
import time


class Airodump(Dependency):
    """ Wrapper around airodump-ng program """
    dependency_required = True
    dependency_name = 'airodump-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'

    def __init__(self, interface=None, channel=None, encryption=None,
                 wps=WPSState.UNKNOWN, target_bssid=None,
                 output_file_prefix='airodump',
                 ivs_only=False, skip_wps=False, delete_existing_files=True):
        """Sets up airodump arguments, doesn't start process yet."""
        Configuration.initialize()

        if interface is None:
            interface = Configuration.interface
        if interface is None:
            raise Exception('Wireless interface must be defined (-i)')
        self.interface = interface
        self.targets = []

        if channel is None:
            channel = Configuration.target_channel
        self.channel = channel
        self.all_bands = Configuration.all_bands
        self.two_ghz = Configuration.two_ghz
        self.five_ghz = Configuration.five_ghz

        self.encryption = encryption
        self.wps = wps

        self.target_bssid = target_bssid
        self.output_file_prefix = output_file_prefix
        self.ivs_only = ivs_only
        self.skip_wps = skip_wps

        # For tracking decloaked APs (previously were hidden)
        self.decloaking = False
        self.decloaked_times = {}  # Map of BSSID(str) -> epoch(int) of last deauth

        self.delete_existing_files = delete_existing_files

    def __enter__(self):
        """
        Setting things up for this context.
        Called at start of 'with Airodump(...) as x:'
        Actually starts the airodump process.
        """
        if self.delete_existing_files:
            self.delete_airodump_temp_files(self.output_file_prefix)

        self.csv_file_prefix = Configuration.temp() + self.output_file_prefix

        # Build the command
        command = [
            'airodump-ng',
            self.interface,
            '--background', '1', # Force "background mode" since we rely on csv instead of stdout
            '-a',  # Only show associated clients
            '-w', self.csv_file_prefix,  # Output file prefix
            '--write-interval', '1'  # Write every second
        ]
        if self.channel:
            command.extend(['-c', str(self.channel)])
        elif self.all_bands:
            command.extend(['--band', 'abg'])
        elif self.two_ghz:
            command.extend(['--band', 'bg'])
        elif self.five_ghz:
            command.extend(['--band', 'a'])

        if self.encryption:
            command.extend(['--enc', self.encryption])
        if self.wps:
            command.extend(['--wps'])
        if self.target_bssid:
            command.extend(['--bssid', self.target_bssid])

        if self.ivs_only:
            command.extend(['--output-format', 'ivs,csv'])
        else:
            command.extend(['--output-format', 'pcap,csv'])

        # Store value for debugging
        self.command = command

        # Start the process
        self.pid = Process(command, devnull=True)
        return self

    def __exit__(self, type2, value, traceback):
        """
        Tearing things down since the context is being exited.
        Called after 'with Airodump(...)' goes out of scope.
        """
        # Kill the process
        self.pid.interrupt()

        if self.delete_existing_files:
            self.delete_airodump_temp_files(self.output_file_prefix)

    def find_files(self, endswith=None):
        return self.find_files_by_output_prefix(self.output_file_prefix, endswith=endswith)

    @classmethod
    def find_files_by_output_prefix(cls, output_file_prefix, endswith=None):
        """ Finds all files in the temp directory that start with the output_file_prefix """
        result = []
        temp = Configuration.temp()
        for fil in os.listdir(temp):
            if not fil.startswith(output_file_prefix):
                continue

            if endswith is None or fil.endswith(endswith):
                result.append(os.path.join(temp, fil))

        return result

    @classmethod
    def delete_airodump_temp_files(cls, output_file_prefix):
        """
        Deletes airodump* files in the temp directory.
        Also deletes replay_*.cap and *.xor files in pwd.
        """
        # Remove all temp files
        for fil in cls.find_files_by_output_prefix(output_file_prefix):
            os.remove(fil)

        # Remove .cap and .xor files from pwd
        for fil in os.listdir('.'):
            if fil.startswith('replay_') and fil.endswith('.cap') or fil.endswith('.xor'):
                os.remove(fil)

        # Remove replay/cap/xor files from temp
        temp_dir = Configuration.temp()
        for fil in os.listdir(temp_dir):
            if fil.startswith('replay_') and fil.endswith('.cap') or fil.endswith('.xor'):
                os.remove(os.path.join(temp_dir, fil))

    def get_targets(self, old_targets=None, apply_filter=True, target_archives=None):
        """ Parses airodump's CSV file, returns list of Targets """

        if old_targets is None:
            old_targets = []
        if target_archives is None:
            target_archives = {}
        # Find the .CSV file
        csv_filename = None
        for fil in self.find_files(endswith='.csv'):
            csv_filename = fil  # Found the file
            break

        if csv_filename is None or not os.path.exists(csv_filename):
            return self.targets  # No file found

        new_targets = Airodump.get_targets_from_csv(csv_filename)

        # Check if one of the targets is also contained in the old_targets
        for new_target in new_targets:
            just_found = True
            for old_target in old_targets:
                # If the new_target is found in old_target copy attributes from old target
                if old_target == new_target:
                    # Identify decloaked targets
                    if new_target.essid_known and not old_target.essid_known:
                        # We decloaked a target!
                        new_target.decloaked = True

                    old_target.transfer_info(new_target)
                    just_found = False
                    break

            # If the new_target is not in old_targets, check target_archives
            # and copy attributes from there
            if just_found and new_target.bssid in target_archives:
                target_archives[new_target.bssid].transfer_info(new_target)

        # Check targets for WPS
        if not self.skip_wps:
            capfile = f'{csv_filename[:-3]}cap'
            try:
                Tshark.check_for_wps_and_update_targets(capfile, new_targets)
            except ValueError:
                # No tshark, or it failed. Fall-back to wash
                Wash.check_for_wps_and_update_targets(capfile, new_targets)

        if apply_filter:
            # Filter targets based on encryption, WPS capability & power
            new_targets = Airodump.filter_targets(new_targets, skip_wps=self.skip_wps)

        # Sort by power
        new_targets.sort(key=lambda x: x.power, reverse=True)

        self.targets = new_targets
        self.deauth_hidden_targets()

        return self.targets

    @staticmethod
    def get_targets_from_csv(csv_filename):
        """Returns list of Target objects parsed from CSV file."""
        targets2 = []
        import chardet
        import csv

        with open(csv_filename, "rb") as rawdata:
            encoding = chardet.detect(rawdata.read())['encoding']

        with open(csv_filename, 'r', encoding=encoding, errors='ignore') as csvopen:
            lines = []
            for line in csvopen:
                line = line.replace('\0', '')
                lines.append(line)

            csv_reader = csv.reader(lines,
                                    delimiter=',',
                                    quoting=csv.QUOTE_ALL,
                                    skipinitialspace=True,
                                    escapechar='\\')

            hit_clients = False
            for row in csv_reader:
                # Each 'row' is a list of fields for a target/client
                if len(row) == 0:
                    continue

                if row[0].strip() == 'BSSID':
                    # This is the 'header' for the list of Targets
                    hit_clients = False
                    continue

                elif row[0].strip() == 'Station MAC':
                    # This is the 'header' for the list of Clients
                    hit_clients = True
                    continue

                if hit_clients:
                    # The current row corresponds to a 'Client' (computer)
                    try:
                        client = Client(row)
                    except (IndexError, ValueError):
                        # Skip if we can't parse the client row
                        continue

                    if 'not associated' in client.bssid:
                        # Ignore unassociated clients
                        continue

                    # Add this client to the appropriate Target
                    for t in targets2:
                        if t.bssid == client.bssid:
                            t.clients.append(client)
                            break

                else:
                    # The current row corresponds to a 'Target' (router)
                    try:
                        target4 = Target(row)
                        targets2.append(target4)
                    except Exception as e:
                        print(f"Error parsing target: {e}")
                continue

        return targets2

    @staticmethod
    def filter_targets(targets5, skip_wps=False):
        """ Filters targets based on Configuration """
        result = []
        # Filter based on Encryption
        active_filters = Configuration.encryption_filter
        # If no specific encryption type filter is active (e.g. --wep, --wpa, --wpa3, --owe, --wps),
        # then all types are considered. The default `Configuration.encryption_filter` is ['WEP', 'WPA', 'WPA3', 'OWE', 'WPS']
        # So, if active_filters contains all of these, it means no specific filter was applied by the user.

        is_filtering_specific_type = len(active_filters) < 5 # Heuristic: 5 is the current total number of distinct filterable types

        for target_obj in targets5: # Renamed target2 to target_obj for clarity
            # Power and client count filters apply universally
            if Configuration.min_power > 0 and target_obj.max_power < Configuration.min_power:
                continue
            if Configuration.clients_only and len(target_obj.clients) == 0:
                continue

            # Encryption type filtering
            # The target_obj.encryption holds the *primary* encryption type like "WPA3", "WPA", "WEP", "OWE"
            # The target_obj.wps holds WPS state.

            # If no specific encryption filter is set by the user, or if skip_wps is True (which implies we are in an attack context not discovery)
            # then we don't filter by encryption type here, BSSID/ESSID filters below will still apply.
            # The main purpose of Configuration.encryption_filter is for user-driven discovery filtering.
            if not is_filtering_specific_type and not skip_wps: # If not filtering by specific type during discovery
                 result.append(target_obj)
                 continue

            # Apply active filters
            added = False
            if 'WEP' in active_filters and target_obj.primary_encryption == 'WEP':
                result.append(target_obj)
                added = True
            elif 'WPA' in active_filters and target_obj.primary_encryption in ['WPA', 'WPA2']: # --wpa flag covers WPA and WPA2
                result.append(target_obj)
                added = True
            elif 'WPA3' in active_filters and target_obj.primary_encryption == 'WPA3':
                result.append(target_obj)
                added = True
            elif 'OWE' in active_filters and target_obj.primary_encryption == 'OWE':
                result.append(target_obj)
                added = True

            # WPS filter can be combined. If a WPA/WPA2/WPA3 network also has WPS and --wps is specified.
            # However, OWE and WEP typically don't have WPS in a meaningful way for these attacks.
            if 'WPS' in active_filters and target_obj.wps in [WPSState.UNLOCKED, WPSState.LOCKED]:
                if target_obj.primary_encryption in ['WPA', 'WPA2', 'WPA3']: # Only add if WPS is relevant to the base encryption
                    if not added: # Avoid duplicate append if already added by WPA/WPA3 filter
                        result.append(target_obj)
                        added = True

            if skip_wps and not added : # If we are in an attack context (skip_wps=True) and it hasn't been added by other filters.
                                   # This ensures that if a specific BSSID is targeted for attack, it passes through.
                result.append(target_obj)


        # Filter based on BSSID/ESSID
        bssid = Configuration.target_bssid
        essid = Configuration.target_essid
        i = 0
        while i < len(result):
            if result[i].essid is not None and\
                    Configuration.ignore_essids is not None and\
                    result[i].essid in Configuration.ignore_essids:
                result.pop(i)
            elif Configuration.ignore_cracked and \
                    result[i].bssid in Configuration.ignore_cracked:
                result.pop(i)
            elif bssid and result[i].bssid.lower() != bssid.lower():
                result.pop(i)
            elif essid and result[i].essid and result[i].essid != essid:
                result.pop(i)
            else:
                i += 1
        return result

    def deauth_hidden_targets(self):
        """
        Sends deauths (to broadcast and to each client) for all
        targets (APs) that have unknown ESSIDs (hidden router names).
        """
        self.decloaking = False

        if Configuration.no_deauth:
            return  # Do not deauth if requested

        if self.channel is None:
            return  # Do not deauth if channel is not fixed.

        # Reusable deauth command
        deauth_cmd = [
            'aireplay-ng',
            '-0',  # Deauthentication
            str(Configuration.num_deauths),  # Number of deauth packets to send
            '--ignore-negative-one'
        ]

        for target3 in self.targets:
            if target3.essid_known:
                continue

            now = int(time.time())
            secs_since_decloak = now - self.decloaked_times.get(target3.bssid, 0)

            if secs_since_decloak < 30:
                continue  # Decloak every AP once every 30 seconds

            self.decloaking = True
            self.decloaked_times[target3.bssid] = now
            if Configuration.verbose > 1:
                from ..util.color import Color
                Color.pe('{C} [?] Deauthing %s (broadcast & %d clients){W}' % (target3.bssid, len(target3.clients)))

            # Deauth broadcast
            iface = Configuration.interface
            Process(deauth_cmd + ['-a', target3.bssid, iface])

            # Deauth clients
            for client in target3.clients:
                Process(deauth_cmd + ['-a', target3.bssid, '-c', client.bssid, iface])


if __name__ == '__main__':
    ''' Example usage. wlan0mon should be in Monitor Mode '''
    with Airodump() as airodump:

        from time import sleep

        sleep(7)

        from ..util.color import Color

        targets = airodump.get_targets()
        for idx, target in enumerate(targets, start=1):
            Color.pl('   {G}%s %s' % (str(idx).rjust(3), target.to_str()))

    Configuration.delete_temp()
