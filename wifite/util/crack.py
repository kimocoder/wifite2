#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import time
from json import loads
from typing import ClassVar
from ..config import Configuration
from ..util.logger import log_debug
from ..util.input import interactive_input
from ..model.handshake import Handshake
from ..model.pmkid_result import CrackResultPMKID
from ..model.wpa_result import CrackResultWPA
from ..model.sae_result import CrackResultSAE
from ..model.sae_handshake import SAEHandshake
from ..tools.aircrack import Aircrack
from ..tools.cowpatty import Cowpatty
from ..tools.hashcat import Hashcat, HcxPcapngTool
from ..tools.john import John
from ..tools.tshark import Tshark
from ..util.color import Color
from ..util.process import Process
from ..util.sae_crack import SAECracker

def print_cracking_command(tool_name, command_parts):
    """
    Print the exact shell command that would be run for cracking,
    so users can copy-paste it into a terminal.

    Used by cracking helpers that need a consistently formatted command line.

    Args:
        tool_name:     Human-readable label for the tool (e.g. 'aircrack-ng').
        command_parts: List of strings forming the shell command (argv style).
    """
    import shlex
    from ..util.color import Color
    cmd_str = ' '.join(shlex.quote(str(p)) for p in command_parts)
    Color.pl('{+} {C}[crack-cmd]{W} {G}%s{W}: {W}%s' % (tool_name, cmd_str))

def decode_hex_essid_if_needed(essid):
    """
    Decode hex-encoded ESSID with strict validation to prevent false positives.
    
    Only decodes if ALL of the following criteria are met:
    1. Length >= 16 characters (minimum for 8-char ESSID encoded as hex)
    2. Length is even (valid hex pairs)
    3. All characters are valid hexadecimal digits
    4. Decoded result is shorter than original (hex encoding expands length)
    5. Decoded result contains only printable characters (ASCII 32-126 or UTF-8 >= 128)
    
    This prevents false positives for legitimate network names like "CAFE", "DEAD", "BEEF", etc.
    
    Args:
        essid: ESSID string to potentially decode
        
    Returns:
        Decoded ESSID if valid hex-encoded, otherwise original ESSID
    """
    # Validation check 1: Minimum length (too short to be hex-encoded)
    if len(essid) < 16:
        return essid
    
    # Validation check 2: Even length (valid hex pairs)
    if len(essid) % 2 != 0:
        return essid
    
    # Validation check 3: All characters are hex digits
    if not all(c in '0123456789ABCDEFabcdef' for c in essid):
        return essid
    
    try:
        # Try to decode from hex with strict error handling
        decoded_essid = bytes.fromhex(essid).decode('utf-8', errors='strict')
        
        # Validation check 4: Decoded result must not be empty
        if not decoded_essid or len(decoded_essid) == 0:
            return essid
        
        # Validation check 5: Hex encoding should make string longer, not shorter
        if len(decoded_essid) >= len(essid):
            return essid
        
        # Validation check 6: Check for printable characters (ASCII 32-126 or extended UTF-8)
        if not all(32 <= ord(c) <= 126 or ord(c) >= 128 for c in decoded_essid):
            return essid
        
        # All checks passed, use decoded version
        if Configuration.verbose > 1:
            Color.pl('{+} {C}Decoded hex ESSID: {O}%s{W} -> {G}%s{W}' % (essid, decoded_essid))
        
        return decoded_essid
        
    except (ValueError, UnicodeDecodeError) as e:
        # Decoding failed, keep original
        # This is expected for legitimate network names like "CAFE", "DEAD", etc.
        if Configuration.verbose > 2:
            Color.pl('{!} {O}Hex ESSID decode failed for %s: %s{W}' % (essid, str(e)))
        return essid

class CrackHelper:
    """Manages handshake retrieval, selection, and running the cracking commands."""

    TYPES: ClassVar[dict[str, str]] = {
        '4-WAY': '4-Way Handshake',
        'PMKID': 'PMKID Hash',
        'SAE': 'WPA3-SAE Handshake'
    }

    # Tools for cracking & their dependencies. (RaduNico's code btw!)
    possible_tools: ClassVar[list[tuple[str, list[type]]]] = [
        ('aircrack', [Aircrack]),
        ('hashcat', [Hashcat, HcxPcapngTool]),
        ('john', [John, HcxPcapngTool]),
        ('cowpatty', [Cowpatty])
    ]

    # <essid>_<bssid>[_<YYYY-MM-DDTHH-MM-SS>]; ESSIDs may contain underscores.
    CAPTURE_NAME_RE: ClassVar[re.Pattern] = re.compile(
        r'^(?P<essid>.+)_'
        r'(?P<bssid>(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})'
        r'(?:_(?P<date>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}))?$'
    )

    @staticmethod
    def _skip_reason(hs, missing_tool_deps):
        """Return why a handshake cannot be cracked, or None."""
        hs_type = hs['type']
        if hs_type not in ('PMKID', 'SAE'):
            return None

        required = ['hashcat']
        if hs_type == 'SAE' and hs['filename'].lower().endswith('.cap'):
            required.append('hcxpcapngtool')
        missing = missing_tool_deps.get('hashcat', [])
        absent = [dep for dep in required if dep in missing]
        if absent:
            return (f"{hs_type} cracking requires {', '.join(required)}; "
                    f"missing: {', '.join(absent)}")
        return None

    @classmethod
    def run(cls):
        Configuration.initialize(False)

        # Get wordlist
        if not Configuration.wordlist:
            Color.p('\n{+} Enter wordlist file or directory to use for cracking: {G}')
            user_input = interactive_input()
            Color.p('{W}')

            if not os.path.exists(user_input):
                Color.pl('{!} {R}Wordlist {O}%s{R} not found. Exiting.' % user_input)
                return

            if os.path.isdir(user_input):
                files = sorted([
                    os.path.join(user_input, f)
                    for f in os.listdir(user_input)
                    if os.path.isfile(os.path.join(user_input, f))
                ])
                if not files:
                    Color.pl('{!} {R}Directory {O}%s{R} contains no files. Exiting.' % user_input)
                    return
                Configuration.wordlists = files
                Configuration.wordlist = files[0]
                Color.pl('{+} Using {G}%d{W} wordlist(s) from directory {G}%s{W}' % (len(files), user_input))
            else:
                Configuration.wordlist = user_input
                Configuration.wordlists = [user_input]
            Color.pl('')

        # Get handshakes
        handshakes = cls.get_handshakes()
        if len(handshakes) == 0:
            Color.pl('{!} {O}No handshakes found{W}')
            return

        if Configuration.crack_index:
            hs_to_crack, invalid = cls.parse_selection(
                Configuration.crack_index, handshakes)
            if invalid is not None:
                Color.pl('{!} {R}Invalid --crack-index selection: {O}%s{W}'
                         % invalid)
                return
            if not hs_to_crack:
                Color.pl('{!} {O}No handshakes selected{W}')
                return
        elif Configuration.crack_all:
            hs_to_crack = handshakes[:]
        else:
            hs_to_crack = cls.get_user_selection(handshakes)
            if not hs_to_crack:
                return
        all_pmkid = all(hs['type'] == 'PMKID' for hs in hs_to_crack)
        has_sae = any(hs['type'] == 'SAE' for hs in hs_to_crack)

        # Identify missing tools
        missing_tools = []
        available_tools = []
        for tool, dependencies in cls.possible_tools:
            if missing := [dep for dep in dependencies if not Process.exists(dep.dependency_name)]:
                missing_tools.append((tool, missing))
            elif tool == 'john' and not John.is_wpapsk_capable():
                missing_tools.append((tool, ['john-jumbo (wpapsk format)']))
            else:
                available_tools.append(tool)

        missing_tool_deps = {
            tool: [d if isinstance(d, str) else d.dependency_name for d in deps]
            for tool, deps in missing_tools
        }
        if missing_tools:
            Color.pl('\n{!} {O}Unavailable tools (install to enable):{W}')
            for tool, deps in missing_tools:
                dep_list = ', '.join([
                    d if isinstance(d, str) else d.dependency_name for d in deps
                ])
                Color.pl('     {R}* {R}%s {W}({O}%s{W})' % (tool, dep_list))

        if all_pmkid or has_sae:
            if Configuration.crack_tool and Configuration.crack_tool != 'hashcat':
                Color.pl('{!} {O}PMKID/SAE require hashcat; '
                         'ignoring --crack-tool %s{W}' % Configuration.crack_tool)
            if all_pmkid:
                Color.pl('{!} {O}Note: PMKID hashes can only be cracked using {C}hashcat{W}')
            if has_sae:
                Color.pl('{!} {O}Note: WPA3-SAE handshakes can only be cracked using {C}hashcat{W}')
            tool_name = 'hashcat'
        elif Configuration.crack_tool:
            tool_name = Configuration.crack_tool
            if tool_name not in available_tools:
                Color.pl('{!} {R}Tool "%s" is not available{W}' % tool_name)
                return
        else:
            Color.p('\n{+} Enter the {C}cracking tool{W} to use ({C}%s{W}): {G}' % (
                '{W}, {C}'.join(available_tools)))
            tool_name = interactive_input().strip()
            Color.p('{W}')

            if tool_name not in available_tools:
                Color.pl('{!} {R}"%s"{O} tool not found, defaulting to {C}aircrack{W}' % tool_name)
                tool_name = 'aircrack'

        try:
            for hs in hs_to_crack:
                reason = cls._skip_reason(hs, missing_tool_deps)
                if reason:
                    Color.pl('{!} {O}%s{W}' % reason)
                    continue
                cls.crack(hs, tool_name)
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}Interrupted{W}')

    @classmethod
    def cracked_filenames(cls):
        """Load the basenames of captures already recorded in cracked.json."""
        if not os.path.exists(Configuration.cracked_file):
            return set()
        try:
            with open(Configuration.cracked_file) as f:
                results = loads(f.read())
        except (OSError, ValueError, TypeError) as e:
            log_debug('CrackHelper',
                      f'Could not read {Configuration.cracked_file}: {e}')
            return set()
        if not isinstance(results, list):
            return set()

        names = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            for key, value in result.items():
                if 'file' in key and isinstance(value, str) and value:
                    names.add(os.path.basename(value))
        return names

    @classmethod
    def is_cracked(cls, file, cracked_names=None):
        if cracked_names is None:
            cracked_names = cls.cracked_filenames()
        return file in cracked_names

    @classmethod
    def _parse_capture(cls, hs_file, full_path):
        """Parse a capture filename into a handshake dict, or None."""
        lowered = hs_file.lower()
        if lowered.endswith('.cap'):
            if hs_file.startswith('sae_handshake_'):
                hs_type, prefix, stem = 'SAE', 'sae_handshake_', hs_file[:-4]
            elif hs_file.startswith('handshake_'):
                hs_type, prefix, stem = '4-WAY', 'handshake_', hs_file[:-4]
            else:
                return None
        elif lowered.endswith('.22000'):
            # Hashcat mode 22000 covers both PMKID and SAE hashes.
            if hs_file.startswith('sae_handshake_'):
                hs_type, prefix = 'SAE', 'sae_handshake_'
            elif hs_file.startswith('pmkid_'):
                hs_type, prefix = 'PMKID', 'pmkid_'
            else:
                hs_type, prefix = 'PMKID', ''
            stem = hs_file[:-6]
        else:
            return None

        if prefix:
            if not stem.startswith(prefix):
                return None
            stem = stem[len(prefix):]

        match = cls.CAPTURE_NAME_RE.fullmatch(stem)
        if match is None:
            return None

        raw_date = match.group('date')
        if raw_date:
            days, hours = raw_date.split('T', 1)
            date = f'{days} {hours.replace("-", ":")}'
        else:
            # SAEHandshake.save() omits the date; fall back to the file mtime.
            date = time.strftime('%Y-%m-%d %H:%M:%S',
                                 time.localtime(os.path.getmtime(full_path)))

        return {
            'filename': full_path,
            'bssid': match.group('bssid').replace('-', ':'),
            'essid': match.group('essid'),
            'date': date,
            'type': hs_type,
        }

    @classmethod
    def get_handshakes(cls):
        handshakes = []

        skipped_hash_files = skipped_cracked_files = skipped_invalid_files = 0
        cracked_names = cls.cracked_filenames()
        has_validator = Tshark.exists() or HcxPcapngTool.exists()

        hs_dir = Configuration.wpa_handshake_dir
        if not os.path.exists(hs_dir) or not os.path.isdir(hs_dir):
            Color.pl('\n{!} {O}directory not found: {R}%s{W}' % hs_dir)
            return []

        Color.pl('\n{+} Listing captured handshakes from {C}%s{W}:\n' % os.path.abspath(hs_dir))
        for hs_file in os.listdir(hs_dir):
            full_path = os.path.join(hs_dir, hs_file)
            if not os.path.isfile(full_path):
                continue

            handshake = cls._parse_capture(hs_file, full_path)
            if handshake is None:
                if Configuration.verbose > 0:
                    Color.pl('{!} {O}Skipping unrecognized capture: %s{W}' % hs_file)
                continue

            if handshake['type'] in ('PMKID', 'SAE'):
                needs_conversion = (handshake['type'] == 'SAE'
                                    and hs_file.lower().endswith('.cap'))
                if (not Process.exists('hashcat')
                        or (needs_conversion
                            and not Process.exists('hcxpcapngtool'))):
                    skipped_hash_files += 1
                    continue

            if cls.is_cracked(hs_file, cracked_names):
                skipped_cracked_files += 1
                continue

            if handshake['type'] == '4-WAY':
                # Prefer the ESSID from the capture when it can be recovered.
                handshakenew = Handshake(full_path)
                valid = True
                try:
                    handshakenew.divine_bssid_and_essid()
                    if handshakenew.essid:
                        handshake['essid'] = handshakenew.essid
                    if has_validator:
                        valid = handshakenew.has_handshake()
                except Exception as e:
                    log_debug('CrackHelper',
                              f'Could not validate {hs_file}: {e}')
                    valid = False
                if not valid:
                    skipped_invalid_files += 1
                    continue
            elif handshake['type'] == 'PMKID' or hs_file.lower().endswith('.22000'):
                # Decode hex-encoded ESSID from passive PMKID/SAE captures
                # with strict validation to prevent false positives.
                handshake['essid'] = decode_hex_essid_if_needed(handshake['essid'])

            handshakes.append(handshake)

        if skipped_hash_files > 0:
            Color.pl(
                '{!} {O}Skipping %d PMKID/SAE capture(s) because '
                '{R}hashcat/hcxtools{O} is missing.{W}\n' % skipped_hash_files)
        if skipped_invalid_files > 0:
            Color.pl('{!} {O}Skipping %d capture(s) with no crackable handshake.{W}\n'
                     % skipped_invalid_files)
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
    def parse_selection(cls, choices, handshakes):
        """Parse 1,3-5 / all into a list; returns (selection, invalid_choice)."""
        if not choices:
            return [], None
        if choices.strip().lower() == 'all':
            return list(handshakes), None

        total = len(handshakes)
        selection = []
        seen = set()
        for choice in choices.split(','):
            choice = choice.strip()
            if not choice:
                continue
            if '-' in choice:
                bounds = [part.strip() for part in choice.split('-')]
                if len(bounds) != 2 or not all(p.isdigit() for p in bounds):
                    return [], choice
                first, last = (int(part) for part in bounds)
                if not (1 <= first <= total and 1 <= last <= total) or first > last:
                    return [], choice
                range_items = handshakes[first - 1:last]
            else:
                if not choice.isdigit():
                    return [], choice
                index = int(choice)
                if not 1 <= index <= total:
                    return [], choice
                range_items = [handshakes[index - 1]]

            for handshake in range_items:
                filename = handshake['filename']
                if filename not in seen:
                    seen.add(filename)
                    selection.append(handshake)
        return selection, None

    @classmethod
    def get_user_selection(cls, handshakes):
        cls.print_handshakes(handshakes)
        total = len(handshakes)
        if total == 0:
            return []

        while True:
            Color.p(
                '{+} Select handshake(s) to crack ({G}%d{W}-{G}%d{W}, select multiple with '
                '{C},{W} or {C}-{W} or {C}all{W}): {G}' % (1, total))
            choices = interactive_input().strip()
            Color.p('{W}')

            if not choices:
                Color.pl('{!} {O}Please enter a selection, or "all".{W}')
                continue

            selection, invalid = cls.parse_selection(choices, handshakes)
            if invalid is not None:
                Color.pl('{!} {R}Invalid selection: {O}%s{W} (choose 1-%d)'
                         % (invalid, total))
                continue
            if not selection:
                Color.pl('{!} {O}Please enter a selection, or "all".{W}')
                continue
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
            if hs['filename'].lower().endswith('.22000'):
                # Already a mode-22000 hash; no pcap conversion needed.
                crack_result = cls.crack_pmkid(
                    hs, tool, result_cls=CrackResultSAE)
            else:
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
        handshake = Handshake(hs['filename'],
                              bssid=hs['bssid'],
                              essid=hs['essid'])
        try:
            handshake.divine_bssid_and_essid()
        except ValueError as e:
            Color.pl('{!} {R}Error: {O}%s{W}' % e)
            return None

        # show_command is True when verbose or when --print-crack-cmd is set
        show_cmd = Configuration.show_cracking_command or Configuration.verbose > 0

        wordlists_to_try = Configuration.wordlists if Configuration.wordlists else [Configuration.wordlist]

        for wordlist in wordlists_to_try:
            wordlist_name = os.path.basename(wordlist)
            Color.pl('{+} Trying wordlist: {C}%s{W}' % wordlist_name)

            key = None
            if tool == 'aircrack':
                key = Aircrack.crack_handshake(handshake, show_command=show_cmd, wordlist=wordlist)
            elif tool == 'hashcat':
                key = Hashcat.crack_handshake(handshake, target_is_wpa3_sae=False, show_command=show_cmd, wordlist=wordlist)
            elif tool == 'john':
                key = John.crack_handshake(handshake, show_command=show_cmd, wordlist=wordlist)
            elif tool == 'cowpatty':
                key = Cowpatty.crack_handshake(handshake, show_command=show_cmd, wordlist=wordlist)

            if key is not None:
                return CrackResultWPA(hs['bssid'], hs['essid'], hs['filename'], key)

        return None

    @classmethod
    def crack_pmkid(cls, hs, tool, result_cls=CrackResultPMKID):
        if tool != 'hashcat':
            Color.pl('{+} {C}Note:{W} PMKID/SAE hashes are cracked with '
                     '{C}hashcat{W}')

        # show_command is True when verbose or when --print-crack-cmd is set
        show_cmd = Configuration.show_cracking_command or Configuration.verbose > 0

        wordlists_to_try = Configuration.wordlists if Configuration.wordlists else [Configuration.wordlist]

        for wordlist in wordlists_to_try:
            wordlist_name = os.path.basename(wordlist)
            Color.pl('{+} Trying wordlist: {C}%s{W}' % wordlist_name)
            key2 = Hashcat.crack_pmkid(hs['filename'], verbose=show_cmd, wordlist=wordlist)
            if key2 is not None:
                return result_cls(hs['bssid'], hs['essid'],
                                  hs['filename'], key2)

        return None

    @classmethod
    def crack_sae(cls, hs, tool):
        """Crack WPA3-SAE handshake using hashcat."""
        if tool != 'hashcat':
            Color.pl('{!} {O}Note: WPA3-SAE handshakes can only be cracked using {C}hashcat{W}')
            return None

        # show_command is True when verbose or when --print-crack-cmd is set
        show_cmd = Configuration.show_cracking_command or Configuration.verbose > 0

        # Create SAEHandshake object
        sae_handshake = SAEHandshake(
            capfile=hs['filename'],
            bssid=hs['bssid'],
            essid=hs['essid']
        )

        wordlists_to_try = Configuration.wordlists if Configuration.wordlists else [Configuration.wordlist]

        for wordlist in wordlists_to_try:
            wordlist_name = os.path.basename(wordlist)
            Color.pl('{+} Trying wordlist: {C}%s{W}' % wordlist_name)
            key = SAECracker.crack_sae_handshake(
                sae_handshake,
                wordlist=wordlist,
                show_command=show_cmd,
                verbose=show_cmd
            )
            if key is not None:
                return CrackResultSAE(hs['bssid'], hs['essid'], hs['filename'], key)

        return None

if __name__ == '__main__':
    CrackHelper.run()
