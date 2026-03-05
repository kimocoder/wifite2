#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color
from ..util.logger import log_debug, log_info, log_warning, log_error
import os

hccapx_autoremove = False  # change this to True if you want the hccapx files to be automatically removed


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'

    @staticmethod
    def should_use_force():
        command = ['hashcat', '-I']
        stderr = Process(command).stderr()
        return 'No devices found/left' in stderr or 'Unstable OpenCL driver detected!' in stderr

    @staticmethod
    def crack_handshake(handshake_obj, target_is_wpa3_sae, show_command=False):
        """
        Cracks a handshake.
        handshake_obj: A Handshake object (should have .capfile attribute)
        target_is_wpa3_sae: Boolean indicating if the target uses WPA3-SAE
        """
        hash_file = HcxPcapngTool.generate_hash_file(handshake_obj, target_is_wpa3_sae, show_command=show_command)

        # If hash file generation failed due to capture quality, fall back to aircrack-ng
        if hash_file is None:
            Color.pl('{!} {O}Falling back to aircrack-ng for cracking{W}')
            from .aircrack import Aircrack
            return Aircrack.crack_handshake(handshake_obj, show_command=show_command)

        key = None
        try:
            # Mode 22000 supports both WPA/WPA2 and WPA3-SAE (WPA-PBKDF2-PMKID+EAPOL)
            hashcat_mode = '22000'
            file_type_msg = "WPA3-SAE hash" if target_is_wpa3_sae else "WPA/WPA2 hash"

            Color.pl(f"{{+}} {{C}}Attempting to crack {file_type_msg} using Hashcat mode {hashcat_mode}{{W}}")

            # Crack hash_file
            for additional_arg in ([], ['--show']):
                command = [
                    'hashcat',
                    '--quiet',
                    '-m', hashcat_mode,
                    hash_file,
                    Configuration.wordlist
                ]
                if Hashcat.should_use_force():
                    command.append('--force')
                command.extend(additional_arg)
                if show_command:
                    Color.pl(f'{{+}} {{D}}Running: {{W}}{{P}}{" ".join(command)}{{W}}')
                process = Process(command)
                stdout, stderr = process.get_output()

                # Check for errors first
                if 'No hashes loaded' in stdout or 'No hashes loaded' in stderr:
                    continue  # No valid hashes to crack

                if ':' not in stdout:
                    continue  # No cracked results

                # Parse the key from hashcat output
                # Expected format: hash:password
                lines = stdout.strip().split('\n')
                for line in lines:
                    if ':' in line and not line.startswith('The plugin') and 'hashcat.net' not in line:
                        # Take the last part after the last colon as the password
                        parts = line.split(':')
                        if len(parts) >= 2:
                            key = parts[-1].strip()
                            if key and len(key) > 0:
                                break
                else:
                    continue
                break

            return key
        finally:
            # Cleanup temporary hash file
            if hash_file and os.path.exists(hash_file):
                try:
                    os.remove(hash_file)
                    if Configuration.verbose > 1:
                        Color.pl('{!} {O}Cleaned up temporary hash file{W}')
                except OSError as e:
                    if Configuration.verbose > 0:
                        Color.pl('{!} {O}Warning: Could not remove hash file: %s{W}' % str(e))

    @staticmethod
    def crack_pmkid(pmkid_file, verbose=False):
        """
        Cracks a given pmkid_file using the PMKID/WPA2 attack (-m 22000)
        Returns:
            Key (str) if found; `None` if not found.
        """

        # Run hashcat once normally, then with --show if it failed
        # To catch cases where the password is already in the pot file.
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',      # Only output the password if found.
                '-m', '22000',  # WPA-PMKID-PBKDF2
                '-a', '0',      # Wordlist attack-mode
                pmkid_file,
                Configuration.wordlist,
                '-w', '3'
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if verbose and additional_arg == []:
                Color.pl(f'{{+}} {{D}}Running: {{W}}{{P}}{" ".join(command)}{{W}}')

            # TODO: Check status of hashcat (%); it's impossible with --quiet

            hashcat_proc = Process(command)
            hashcat_proc.wait()
            stdout = hashcat_proc.stdout()

            if ':' not in stdout:
                # Failed
                continue
            else:
                # Hashcat PMKID output format: hash*bssid*station*essid:password
                # We only want the password (last part after the last colon)
                return stdout.strip().split(':')[-1]


class HcxDumpTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'apt install hcxdumptool'

    def __init__(self, target, pcapng_file):
        if os.path.exists(pcapng_file):
            os.remove(pcapng_file)

        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '-c', str(target.channel) + 'a',
            '-w', pcapng_file
        ]

        self.proc = Process(command)

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        if hasattr(self, 'proc') and self.proc:
            self.proc.interrupt()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.interrupt()


class HcxPcapngTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxpcapngtool'
    dependency_url = 'apt install hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.pmkid_file = Configuration.temp(f'pmkid-{self.bssid}.22000')

    @staticmethod
    def generate_hash_file(handshake_obj, is_wpa3_sae, show_command=False):
        """
        Generates a hash file suitable for Hashcat.
        For WPA/WPA2, generates hash file for mode 22000.
        For WPA3-SAE, generates hash file for mode 22001.
        Both use the same hcxpcapngtool -o flag, as mode 22000 supports both WPA2 and WPA3-SAE.
        """
        import tempfile
        
        hash_type = "WPA3-SAE" if is_wpa3_sae else "WPA/WPA2"
        log_info('HcxPcapngTool', f'Generating {hash_type} hash file from capture: {handshake_obj.capfile}')
        
        # Use mode 22000 format for both WPA2 and WPA3-SAE
        # Hashcat mode 22000 supports WPA-PBKDF2-PMKID+EAPOL (includes SAE)
        # Mode 22001 is for WPA-PMK-PMKID+EAPOL (pre-computed PMK)

        # Create secure temporary file with proper permissions (0600)
        # Using NamedTemporaryFile with delete=False to prevent race conditions
        log_debug('HcxPcapngTool', 'Creating secure temporary hash file')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.22000', delete=False, prefix='wifite_hash_') as tmp:
            hash_file = tmp.name

        # Verify file permissions are secure (0600)
        os.chmod(hash_file, 0o600)
        log_debug('HcxPcapngTool', f'Created temporary hash file: {hash_file} (permissions: 0600)')

        try:
            command = [
                'hcxpcapngtool',
                '-o', hash_file,
                handshake_obj.capfile # Assuming handshake_obj has a capfile attribute
            ]

            log_debug('HcxPcapngTool', f'Running hcxpcapngtool: {" ".join(command)}')
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

            process = Process(command)
            stdout, stderr = process.get_output()

            log_debug('HcxPcapngTool', f'hcxpcapngtool stdout: {stdout[:200]}...' if len(stdout) > 200 else f'hcxpcapngtool stdout: {stdout}')
            if stderr:
                log_debug('HcxPcapngTool', f'hcxpcapngtool stderr: {stderr[:200]}...' if len(stderr) > 200 else f'hcxpcapngtool stderr: {stderr}')

            if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
                # Check if this is due to missing frames (common with airodump captures)
                if 'no hashes written' in stdout.lower() or 'missing frames' in stdout.lower():
                    log_warning('HcxPcapngTool', 'Hash generation failed: capture quality issue (missing frames)')
                    #Color.pl('{!} {O}Warning: hcxpcapngtool could not extract hash (capture quality issue){W}')
                    #Color.pl('{!} {O}The capture file is missing required frames or metadata{W}')
                    #Color.pl('{!} {O}This is common with airodump-ng captures - consider using hcxdumptool instead{W}')
                    # Cleanup failed hash file
                    if os.path.exists(hash_file):
                        try:
                            os.remove(hash_file)
                            log_debug('HcxPcapngTool', 'Cleaned up empty hash file')
                        except OSError:
                            pass
                    # Return None to signal fallback to aircrack-ng should be used
                    return None

                # For other errors, provide detailed error message
                error_msg = f'Failed to generate {"SAE hash" if is_wpa3_sae else "WPA/WPA2 hash"} file.'
                error_msg += f'\nOutput from hcxpcapngtool:\nSTDOUT: {stdout}\nSTDERR: {stderr}'
                log_error('HcxPcapngTool', f'Hash generation failed: {error_msg}')
                
                # Also include tshark check for WPA3
                if is_wpa3_sae:
                    from .tshark import Tshark
                    tshark_check_cmd = ['tshark', '-r', handshake_obj.capfile, '-Y', 'wlan.fc.type_subtype == 0x0b'] # Authentication frames
                    tshark_process = Process(tshark_check_cmd)
                    tshark_stdout, _ = tshark_process.get_output()
                    if not tshark_stdout:
                        error_msg += '\nAdditionally, tshark found no authentication frames in the capture file. Ensure it is a valid WPA3-SAE handshake.'
                        log_debug('HcxPcapngTool', 'tshark found no authentication frames in capture')
                    else:
                        frame_count = len(tshark_stdout.strip().split(chr(10)))
                        error_msg += f'\nTshark found {frame_count} authentication frames in the capture.'
                        log_debug('HcxPcapngTool', f'tshark found {frame_count} authentication frames')

                raise ValueError(error_msg)
            
            file_size = os.path.getsize(hash_file)
            log_info('HcxPcapngTool', f'Hash file generated successfully: {hash_file} ({file_size} bytes)')
            return hash_file
        except Exception as e:
            # Cleanup hash file on any error
            log_error('HcxPcapngTool', f'Exception during hash generation: {str(e)}', e)
            if hash_file and os.path.exists(hash_file):
                try:
                    os.remove(hash_file)
                    log_debug('HcxPcapngTool', 'Cleaned up temporary hash file after error')
                    if Configuration.verbose > 1:
                        Color.pl('{!} {O}Cleaned up temporary hash file after error{W}')
                except OSError as cleanup_err:
                    log_debug('HcxPcapngTool', f'Failed to cleanup hash file: {str(cleanup_err)}')
                    pass
            raise

    @staticmethod
    def generate_john_file(handshake, show_command=False):
        import tempfile
        
        log_info('HcxPcapngTool', f'Generating John the Ripper file from capture: {handshake.capfile}')
        
        # Create secure temporary file with proper permissions (0600)
        # Using NamedTemporaryFile with delete=False to prevent race conditions
        log_debug('HcxPcapngTool', 'Creating secure temporary john file')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.john', delete=False, prefix='wifite_john_') as tmp:
            john_file = tmp.name
        
        # Verify file permissions are secure (0600)
        os.chmod(john_file, 0o600)
        log_debug('HcxPcapngTool', f'Created temporary john file: {john_file} (permissions: 0600)')

        try:
            command = [
                'hcxpcapngtool',
                '--john', john_file,
                handshake.capfile
            ]

            log_debug('HcxPcapngTool', f'Running hcxpcapngtool: {" ".join(command)}')
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

            process = Process(command)
            stdout, stderr = process.get_output()
            
            log_debug('HcxPcapngTool', f'hcxpcapngtool stdout: {stdout[:200]}...' if len(stdout) > 200 else f'hcxpcapngtool stdout: {stdout}')
            if stderr:
                log_debug('HcxPcapngTool', f'hcxpcapngtool stderr: {stderr[:200]}...' if len(stderr) > 200 else f'hcxpcapngtool stderr: {stderr}')
            
            if not os.path.exists(john_file):
                error_msg = 'Failed to generate .john file, output: \n%s\n%s' % (stdout, stderr)
                log_error('HcxPcapngTool', error_msg)
                raise ValueError(error_msg)

            file_size = os.path.getsize(john_file)
            log_info('HcxPcapngTool', f'John file generated successfully: {john_file} ({file_size} bytes)')
            return john_file
        except Exception as e:
            # Cleanup john file on any error
            log_error('HcxPcapngTool', f'Exception during john file generation: {str(e)}', e)
            if john_file and os.path.exists(john_file):
                try:
                    os.remove(john_file)
                    log_debug('HcxPcapngTool', 'Cleaned up temporary john file after error')
                    if Configuration.verbose > 1:
                        Color.pl('{!} {O}Cleaned up temporary john file after error{W}')
                except OSError as cleanup_err:
                    log_debug('HcxPcapngTool', f'Failed to cleanup john file: {str(cleanup_err)}')
                    pass
            raise

    def get_pmkid_hash(self, pcapng_file):
        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)

        command = 'hcxpcapngtool -o ' + self.pmkid_file + " " + pcapng_file
        hcxpcap_proc = Process(command)
        hcxpcap_proc.wait()

        if not os.path.exists(self.pmkid_file):
            return None

        with open(self.pmkid_file, 'r') as f:
            output = f.read()
            # Each line looks like:
            # hash*bssid*station*essid

        # Note: The dumptool will record *anything* it finds, ignoring the filterlist.
        # Check that we got the right target (filter by BSSID)
        matching_pmkid_hash = None
        for line in output.split('\n'):
            fields = line.split('*')
            if len(fields) >= 3 and fields[3].lower() == self.bssid:
                # Found it
                matching_pmkid_hash = line
                break

        os.remove(self.pmkid_file)
        return matching_pmkid_hash

    @staticmethod
    def extract_all_pmkids(pcapng_file):
        """
        Extract all PMKID hashes from a pcapng file.

        Args:
            pcapng_file: Path to pcapng capture file

        Returns:
            List of dicts: [{'bssid': str, 'essid': str, 'hash': str}, ...]
        """
        import tempfile
        
        log_info('HcxPcapngTool', f'Extracting all PMKIDs from capture: {pcapng_file}')
        
        # Create secure temporary file with proper permissions (0600)
        # Using NamedTemporaryFile with delete=False to prevent race conditions
        log_debug('HcxPcapngTool', 'Creating secure temporary PMKID hash file')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.22000', delete=False, prefix='wifite_pmkids_') as tmp:
            temp_hash_file = tmp.name
        
        # Verify file permissions are secure (0600)
        os.chmod(temp_hash_file, 0o600)
        log_debug('HcxPcapngTool', f'Created temporary PMKID hash file: {temp_hash_file} (permissions: 0600)')

        # Check if pcapng file exists
        if not os.path.exists(pcapng_file):
            log_warning('HcxPcapngTool', f'PMKID extraction failed: capture file not found: {pcapng_file}')
            return []

        command = [
            'hcxpcapngtool',
            '-o', temp_hash_file,
            pcapng_file
        ]

        log_debug('HcxPcapngTool', f'Running hcxpcapngtool: {" ".join(command)}')
        process = Process(command)
        process.wait()

        # If extraction failed or no hashes found, return empty list
        if not os.path.exists(temp_hash_file):
            log_warning('HcxPcapngTool', 'PMKID extraction failed: no hash file generated')
            return []

        pmkids = []
        try:
            with open(temp_hash_file, 'r') as f:
                for line in f:
                    line = line.strip()

                    # Skip empty lines
                    if not line:
                        continue

                    # PMKID hash format: WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID
                    # or: WPA*02*PMKID*MAC_AP*MAC_CLIENT*ESSID (for WPA2)
                    # The hash line should start with 'WPA*'
                    if not line.startswith('WPA*'):
                        continue

                    # Parse hash fields
                    fields = line.split('*')

                    # Need at least 6 fields for a valid PMKID hash
                    if len(fields) < 6:
                        continue

                    # Extract BSSID (MAC_AP), ESSID, and full hash
                    # fields[0] = 'WPA'
                    # fields[1] = type (01 or 02)
                    # fields[2] = PMKID hash
                    # fields[3] = MAC_AP (BSSID)
                    # fields[4] = MAC_CLIENT
                    # fields[5] = ESSID (may be empty or hex-encoded)

                    bssid = fields[3] if len(fields) > 3 else ''
                    essid_hex = fields[5] if len(fields) > 5 else ''

                    # Format BSSID with colons (convert from 'aabbccddeeff' to 'aa:bb:cc:dd:ee:ff')
                    if bssid and len(bssid) == 12:
                        bssid = ':'.join([bssid[i:i+2] for i in range(0, 12, 2)]).upper()

                    # Decode ESSID from hex to ASCII
                    essid = ''
                    if essid_hex:
                        try:
                            # ESSID is hex-encoded, decode it to get the actual network name
                            essid = bytes.fromhex(essid_hex).decode('utf-8', errors='ignore')
                        except (ValueError, UnicodeDecodeError):
                            # If decoding fails, use the hex value as-is
                            essid = essid_hex

                    pmkids.append({
                        'bssid': bssid,
                        'essid': essid,
                        'hash': line
                    })
                    log_debug('HcxPcapngTool', f'Extracted PMKID for {essid} ({bssid})')
            
            log_info('HcxPcapngTool', f'Successfully extracted {len(pmkids)} PMKID(s) from capture')
        except Exception as e:
            # Handle any file reading errors gracefully
            log_error('HcxPcapngTool', f'Error parsing PMKID hashes: {str(e)}', e)
            Color.pl('{!} {R}Error parsing PMKID hashes: {O}%s{W}' % str(e))
        finally:
            # Clean up temporary file
            if os.path.exists(temp_hash_file):
                try:
                    os.remove(temp_hash_file)
                    log_debug('HcxPcapngTool', 'Cleaned up temporary PMKID hash file')
                    if Configuration.verbose > 1:
                        Color.pl('{!} {O}Cleaned up temporary PMKID hash file{W}')
                except OSError as e:
                    log_warning('HcxPcapngTool', f'Failed to cleanup PMKID hash file: {str(e)}')
                    if Configuration.verbose > 0:
                        Color.pl('{!} {O}Warning: Could not remove PMKID hash file: %s{W}' % str(e))

        return pmkids
