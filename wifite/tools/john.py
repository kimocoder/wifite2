#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process
from ..tools.hashcat import HcxPcapngTool

import os


class John(Dependency):
    """ Wrapper for John program. """
    dependency_required = False
    dependency_name = 'john'
    dependency_url = 'https://www.openwall.com/john/'

    @staticmethod
    def crack_handshake(handshake, show_command=False, wordlist=None):
        john_file = HcxPcapngTool.generate_john_file(handshake, show_command=show_command)

        wordlist = wordlist or Configuration.wordlist
        key = None
        try:
            # Use `john --list=formats` to find if OpenCL or CUDA is supported.
            formats_stdout = Process(['john', '--list=formats']).stdout()
            if 'wpapsk-opencl' in formats_stdout:
                john_format = 'wpapsk-opencl'
            elif 'wpapsk-cuda' in formats_stdout:
                john_format = 'wpapsk-cuda'
            else:
                john_format = 'wpapsk'

            # Crack john file
            command = ['john', f'--format={john_format}', f'--wordlist={wordlist}', john_file]
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            process = Process(command)
            process.wait()

            # Run again with --show to consistently get the password
            command = ['john', '--show', john_file]
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            process = Process(command)
            stdout, stderr = process.get_output()

            # Parse password (regex doesn't work for some reason)
            if '0 password hashes cracked' in stdout:
                key = None
            else:
                for line in stdout.split('\n'):
                    if handshake.capfile in line:
                        key = line.split(':')[1]
                        break

            return key
        finally:
            # Cleanup temporary john file
            if john_file and os.path.exists(john_file):
                try:
                    os.remove(john_file)
                    if Configuration.verbose > 1:
                        Color.pl('{!} {O}Cleaned up temporary john file{W}')
                except OSError as e:
                    if Configuration.verbose > 0:
                        Color.pl('{!} {O}Warning: Could not remove john file: %s{W}' % str(e))
