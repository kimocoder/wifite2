#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from json import loads
from ..config import Configuration
from ..model.handshake import Handshake
from ..model.pmkid_result import CrackResultPMKID
from ..model.wpa_result import CrackResultWPA
from ..model.sae_result import CrackResultSAE
from ..model.sae_handshake import SAEHandshake
from ..tools.aircrack import Aircrack
from ..tools.cowpatty import Cowpatty
from ..tools.hashcat import Hashcat, HcxPcapngTool
from ..tools.john import John
from ..util.color import Color
from ..util.process import Process
from ..util.sae_crack import SAECracker


# TODO: Bring back the 'print' option, for easy copy/pasting. Just one-liners people can paste into terminal.

class CrackHelper:
    """Manages handshake retrieval, selection, and running the cracking commands."""

    TYPES = {
        '4-WAY': '4-Way Handshake',
        'PMKID': 'PMKID Hash',
        'SAE': 'WPA3-SAE Handshake'
    }

    # Tools for cracking & their dependencies. (RaduNico's code btw!)
    possible_tools = [
        ('aircrack', [Aircrack]),
        ('hashcat', [Hashcat, HcxPcapngTool]),
        ('john', [John, HcxPcapngTool]),
        ('cowpatty', [Cowpatty])
    ]

    @classmethod
    def run(cls):
        Configuration.initialize(False)

        # Get wordlist
        if not Configuration.wordlist:
            Color.p('\n{+} Enter wordlist file to use for cracking: {G}')
            Configuration.wordlist = input()
            Color.p('{W}')

            if not os.path.exists(Configuration.wordlist):
                Color.pl('{!} {R}Wordlist {O}%s{R} not found. Exiting.' % Configuration.wordlist)
                return
            Color.pl('')

        # Get handshakes
        handshakes = cls.get_handshakes()
        if len(handshakes) == 0:
            Color.pl('{!} {O}No handshakes found{W}')
            return

        hs_to_crack = cls.get_user_selection(handshakes)
        all_pmkid = all(hs['type'] == 'PMKID' for hs in hs_to_crack)
        all_sae = all(hs['type'] == 'SAE' for hs in hs_to_crack)
        has_sae = any(hs['type'] == 'SAE' for hs in hs_to_crack)

        # Identify missing tools
        missing_tools = []
        available_tools = []
        for tool, dependencies in cls.possible_tools:
            if missing := [dep for dep in dependencies if not Process.exists(dep.dependency_name)]:
                missing_tools.append((tool, missing))
            else:
                available_tools.append(tool)

        if missing_tools:
            Color.pl('\n{!} {O}Unavailable tools (install to enable):{W}')
            for tool, deps in missing_tools:
                dep_list = ', '.join([dep.dependency_name for dep in deps])
                Color.pl('     {R}* {R}%s {W}({O}%s{W})' % (tool, dep_list))

        if all_pmkid or all_sae or has_sae:
            if all_pmkid:
                Color.pl('{!} {O}Note: PMKID hashes can only be cracked using {C}hashcat{W}')
            if all_sae or has_sae:
                Color.pl('{!} {O}Note: WPA3-SAE handshakes can only be cracked using {C}hashcat{W}')
            tool_name = 'hashcat'
        else:
            Color.p('\n{+} Enter the {C}cracking tool{W} to use ({C}%s{W}): {G}' % (
                '{W}, {C}'.join(available_tools)))
            tool_name = input()
            Color.p('{W}')

            if tool_name not in available_tools:
                Color.pl('{!} {R}"%s"{O} tool not found, defaulting to {C}aircrack{W}' % tool_name)
                tool_name = 'aircrack'

        try:
            for hs in hs_to_crack:
                if tool_name != 'hashcat' and hs['type'] in ['PMKID', 'SAE'] and 'hashcat' in missing_tools:
                    Color.pl('{!} {O}Hashcat is missing, therefore we cannot crack %s{W}' % hs['type'])
                    continue
                cls.crack(hs, tool_name)
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}Interrupted{W}')

    @classmethod
    def is_cracked(cls, file):
        if not os.path.exists(Configuration.cracked_file):
            return False
        with open(Configuration.cracked_file) as f:
            json = loads(f.read())
        if json is None:
            return False
        for result in json:
            for k in list(result.keys()):
                v = result[k]
                if 'file' in k and os.path.basename(v) == file:
                    return True
        return False

    @classmethod
    def get_handshakes(cls):
        handshakes = []

        skipped_pmkid_files = skipped_cracked_files = 0

        hs_dir = Configuration.wpa_handshake_dir
        if not os.path.exists(hs_dir) or not os.path.isdir(hs_dir):
            Color.pl('\n{!} {O}directory not found: {R}%s{W}' % hs_dir)
            return []

        Color.pl('\n{+} Listing captured handshakes from {C}%s{W}:\n' % os.path.abspath(hs_dir))
        for hs_file in os.listdir(hs_dir):
            if hs_file.count('_') != 3:
                continue

            if cls.is_cracked(hs_file):
                skipped_cracked_files += 1
                continue

            # Determine handshake type
            if hs_file.endswith('.cap'):
                # Check if it's a SAE handshake or regular WPA
                if hs_file.startswith('sae_handshake_'):
                    hs_type = 'SAE'
                else:
                    hs_type = '4-WAY'
            elif hs_file.endswith('.22000'):
                # PMKID hash
                if not Process.exists('hashcat'):
                    skipped_pmkid_files += 1
                    continue
                hs_type = 'PMKID'
            else:
                continue

            # Parse filename: name_essid_bssid_date.ext
            # ESSID can contain underscores, so split from right
            # Expected format: handshake_ESSID_AA-BB-CC-DD-EE-FF_20251031T120000.cap
            try:
                # Remove file extension first
                filename_no_ext = hs_file.rsplit('.', 1)[0]
                
                # Split from right: last 3 parts are always bssid, date (and first is name)
                parts = filename_no_ext.split('_')
                
                if len(parts) < 4:
                    # Malformed filename, skip
                    if Configuration.verbose > 0:
                        Color.pl('{!} {O}Skipping malformed filename: %s{W}' % hs_file)
                    continue
                
                # Extract parts: name is first, bssid and date are last two
                name = parts[0]
                date = parts[-1]
                bssid = parts[-2]
                # Everything in between is the ESSID (may contain underscores)
                essid = '_'.join(parts[1:-2])
                
                # Parse date
                days, hours = date.split('T')
                hours = hours.replace('-', ':')
                date = f'{days} {hours}'
                
            except (ValueError, IndexError) as e:
                # Failed to parse filename
                if Configuration.verbose > 0:
                    Color.pl('{!} {O}Error parsing filename %s: %s{W}' % (hs_file, str(e)))
                continue

            if hs_type == '4-WAY':
                # Patch for essid with " " (zero) or dot "." in name
                handshakenew = Handshake(os.path.join(hs_dir, hs_file))
                handshakenew.divine_bssid_and_essid()
                essid_discovery = handshakenew.essid

                essid = essid if essid_discovery is None else essid_discovery
            elif hs_type == 'PMKID':
                # Decode hex-encoded ESSID from passive PMKID capture
                # Only decode if it looks like hex-encoded UTF-8 (not just valid hex)
                # Criteria:
                # 1. Length >= 16 (minimum for 8-char ESSID encoded as hex)
                # 2. Even length (valid hex pairs)
                # 3. All characters are hex digits
                # 4. Decoded result is shorter than original (hex encoding expands)
                # 5. Decoded result contains only printable characters
                if (len(essid) >= 16 and 
                    len(essid) % 2 == 0 and 
                    all(c in '0123456789ABCDEFabcdef' for c in essid)):
                    try:
                        # Try to decode from hex (strict mode)
                        decoded_essid = bytes.fromhex(essid).decode('utf-8', errors='strict')
                        
                        # Validate decoded result
                        if (decoded_essid and 
                            len(decoded_essid) > 0 and
                            len(decoded_essid) < len(essid) and  # Hex encoding should be longer
                            all(32 <= ord(c) <= 126 or ord(c) >= 128 for c in decoded_essid)):  # Printable chars
                            essid = decoded_essid
                    except (ValueError, UnicodeDecodeError):
                        # If decoding fails, keep the original hex string
                        # This is expected for legitimate network names like "CAFE", "DEAD", etc.
                        pass
            
            handshake = {
                'filename': os.path.join(hs_dir, hs_file),
                'bssid': bssid.replace('-', ':'),
                'essid': essid,
                'date': date,
                'type': hs_type
            }

            handshakes.append(handshake)

        if skipped_pmkid_files > 0:
            Color.pl(
                '{!} {O}Skipping %d {R}*.22000{O} files because {R}hashcat{O} is missing.{W}\n' % skipped_pmkid_files)
        if skipped_cracked_files > 0:
            Color.pl('{!} {O}Skipping %d already cracked files.{W}\n' % skipped_cracked_files)

        # Sort by Date (Descending)
        return sorted(handshakes, key=lambda x: x.get('date'), reverse=True)

    @classmethod
    def print_handshakes(cls, handshakes):
        # Header
        max_essid_len = max([len(hs['essid']) for hs in handshakes] + [len('ESSID (truncated)')])
        Color.p('{W}{D}  NUM')
        Color.p('  ' + 'ESSID (truncated)'.ljust(max_essid_len))
        Color.p('  ' + 'BSSID'.ljust(17))
        Color.p('  ' + 'TYPE'.ljust(5))
        Color.p('  ' + 'DATE CAPTURED\n')
        Color.p('  ---')
        Color.p('  ' + ('-' * max_essid_len))
        Color.p('  ' + ('-' * 17))
        Color.p('  ' + ('-' * 5))
        Color.p('  ' + ('-' * 19) + '{W}\n')
        # Handshakes
        for index, handshake in enumerate(handshakes, start=1):
            Color.p('  {G}%s{W}' % str(index).rjust(3))
            Color.p('  {C}%s{W}' % handshake['essid'].ljust(max_essid_len))
            Color.p('  {O}%s{W}' % handshake['bssid'].ljust(17))
            Color.p('  {C}%s{W}' % handshake['type'].ljust(5))
            Color.p('  {W}%s{W}\n' % handshake['date'])

    @classmethod
    def get_user_selection(cls, handshakes):
        cls.print_handshakes(handshakes)

        Color.p(
            '{+} Select handshake(s) to crack ({G}%d{W}-{G}%d{W}, select multiple with '
            '{C},{W} or {C}-{W} or {C}all{W}): {G}' % (1, len(handshakes)))
        choices = input()
        Color.p('{W}')

        selection = []
        for choice in choices.split(','):
            if '-' in choice:
                first, last = [int(x) for x in choice.split('-')]
                for index in range(first, last + 1):
                    selection.append(handshakes[index - 1])
            elif choice.strip().lower() == 'all':
                selection = handshakes[:]
                break
            elif [c.isdigit() for c in choice]:
                index = int(choice)
                selection.append(handshakes[index - 1])

        return selection

    @classmethod
    def crack(cls, hs, tool):
        Color.pl('\n{+} Cracking {G}%s {C}%s{W} ({C}%s{W})' % (
            cls.TYPES[hs['type']], hs['essid'], hs['bssid']))

        if hs['type'] == 'PMKID':
            crack_result = cls.crack_pmkid(hs, tool)
        elif hs['type'] == '4-WAY':
            crack_result = cls.crack_4way(hs, tool)
        elif hs['type'] == 'SAE':
            crack_result = cls.crack_sae(hs, tool)
        else:
            raise ValueError(f'Cannot crack handshake: Type is not PMKID, 4-WAY, or SAE. Handshake={hs}')

        if crack_result is None:
            # Failed to crack
            Color.pl('{!} {R}Failed to crack {O}%s{R} ({O}%s{R}): Passphrase not in dictionary' % (
                hs['essid'], hs['bssid']))
        else:
            # Cracked, replace existing entry (if any), or add to
            Color.pl('{+} {G}Cracked{W} {C}%s{W} ({C}%s{W}). Key: "{G}%s{W}"' % (
                hs['essid'], hs['bssid'], crack_result.key))
            crack_result.save()

    @classmethod
    def crack_4way(cls, hs, tool):
        global key
        handshake = Handshake(hs['filename'],
                              bssid=hs['bssid'],
                              essid=hs['essid'])
        try:
            handshake.divine_bssid_and_essid()
        except ValueError as e:
            Color.pl('{!} {R}Error: {O}%s{W}' % e)
            return None

        if tool == 'aircrack':
            key = Aircrack.crack_handshake(handshake, show_command=True)
        elif tool == 'hashcat':
            key = Hashcat.crack_handshake(handshake, target_is_wpa3_sae=False, show_command=True)
        elif tool == 'john':
            key = John.crack_handshake(handshake, show_command=True)
        elif tool == 'cowpatty':
            key = Cowpatty.crack_handshake(handshake, show_command=True)

        if key is not None:
            return CrackResultWPA(hs['bssid'], hs['essid'], hs['filename'], key)
        else:
            return None

    @classmethod
    def crack_pmkid(cls, hs, tool):
        if tool != 'hashcat':
            Color.pl('{!} {O}Note: PMKID hashes can only be cracked using {C}hashcat{W}')

        key2 = Hashcat.crack_pmkid(hs['filename'], verbose=True)

        if key2 is not None:
            return CrackResultPMKID(hs['bssid'], hs['essid'], hs['filename'], key2)
        else:
            return None

    @classmethod
    def crack_sae(cls, hs, tool):
        """Crack WPA3-SAE handshake using hashcat."""
        if tool != 'hashcat':
            Color.pl('{!} {O}Note: WPA3-SAE handshakes can only be cracked using {C}hashcat{W}')
            return None
        
        # Create SAEHandshake object
        sae_handshake = SAEHandshake(
            capfile=hs['filename'],
            bssid=hs['bssid'],
            essid=hs['essid']
        )
        
        # Crack using SAECracker
        key = SAECracker.crack_sae_handshake(
            sae_handshake,
            wordlist=Configuration.wordlist,
            show_command=True,
            verbose=True
        )
        
        if key is not None:
            return CrackResultSAE(hs['bssid'], hs['essid'], hs['filename'], key)
        else:
            return None


if __name__ == '__main__':
    CrackHelper.run()
