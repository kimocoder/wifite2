#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Keyboard input handling for wifite2 TUI.
Provides non-blocking keyboard input for interactive views.
"""

import sys
import select
import re
import shutil
import termios
import tty
from typing import Optional

from .color import Color


def interactive_input():
    """Read a line of interactive input, treating closed stdin like Ctrl+C.

    Non-interactive runs (piped stdin, ``< /dev/null``, CI) used to crash
    at prompts with "Unexpected Error: EOF when reading a line". Every
    prompt site already handles KeyboardInterrupt, so EOF is reported once
    here and raised as KeyboardInterrupt to reuse those graceful exits.
    """
    try:
        return input()
    except EOFError:
        Color.pl('\n{!} {O}No interactive input available (stdin closed); '
                 'aborting prompt{W}')
        raise KeyboardInterrupt


def _terminal_rows(text, columns):
    """Count terminal rows occupied by rendered text starting in column zero."""
    rendered = Color.s(text)
    rendered = re.sub(r'\033\[[0-?]*[ -/]*[@-~]', '', rendered)
    return sum(max(1, len(line) // columns + 1) for line in rendered.split('\n'))


def _clear_terminal_rows(rows):
    """Clear *rows* from the current cursor position and return to their top."""
    sys.stdout.write(f'\033[{rows}A')
    for row in range(rows):
        sys.stdout.write('\r\033[2K')
        if row < rows - 1:
            sys.stdout.write('\033[1B')
    if rows > 1:
        sys.stdout.write(f'\033[{rows - 1}A')
    sys.stdout.write('\r')
    sys.stdout.flush()


def prompt_until_valid(prompt, parser, invalid_message='Invalid input.'):
    """Prompt until *parser* accepts the response, with a clean retry row.

    ``parser`` should return the parsed value or raise ``ValueError`` when the
    response is invalid. Empty input is treated like any other value, so the
    caller can choose whether it is a valid default or should be retried.
    """
    retry = False
    while True:
        if retry:
            if not Color.kalidroid and sys.stdout.isatty():
                # input() leaves the cursor below the echoed answer. Count
                # actual wrapped rows as well as explicit newlines so long
                # prompts don't survive underneath the retry.
                columns = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns)
                _clear_terminal_rows(_terminal_rows(prompt + response, columns))
                Color.pl('{!} {O}%s{W}' % retry_message)
                import time
                time.sleep(2)
                error_rows = _terminal_rows(
                    '{!} {O}%s{W}' % retry_message, columns)
                _clear_terminal_rows(error_rows)
                Color.last_sameline_length = 0
            else:
                Color.pl('{!} {O}%s{W}' % retry_message)

        Color.p(prompt)
        response = interactive_input()
        try:
            return parser(response)
        except ValueError as error:
            retry_message = str(error) or invalid_message
            retry = True


def parse_index_selection(response, maximum, allow_all=True):
    """Parse comma-separated 1-based indices and inclusive ranges.

    Returns zero-based indices. Raises ``ValueError`` for blanks, malformed
    values, reversed ranges, or indices outside ``1..maximum``.
    """
    value = response.strip().lower()
    if allow_all and value == 'all':
        return list(range(maximum))
    if not value:
        raise ValueError(f'Enter a selection from 1 to {maximum}.')

    selected = []
    for part in value.split(','):
        part = part.strip()
        if not part:
            raise ValueError('Use comma-separated numbers or ranges.')
        if '-' in part:
            bounds = part.split('-')
            if not all(bound.strip().isdigit() for bound in bounds):
                raise ValueError('Use ranges like 1-3 or dash-separated numbers.')
            numbers = [int(bound.strip()) for bound in bounds]
            if len(numbers) == 2:
                first, last = numbers
                if first > last:
                    raise ValueError('Range start must not exceed its end.')
                numbers = range(first, last + 1)
        elif part.isdigit():
            numbers = [int(part)]
        else:
            raise ValueError('Use comma-separated numbers or ranges.')

        if any(number < 1 or number > maximum for number in numbers):
            raise ValueError(f'Choose numbers from 1 to {maximum}.')
        selected.extend(number - 1 for number in numbers)

    return list(dict.fromkeys(selected))


def parse_yes_no(response, default=None):
    """Parse a yes/no response, optionally using a default for blank input."""
    value = response.strip().lower()
    if not value and default is not None:
        return bool(default)
    if value in ('y', 'yes'):
        return True
    if value in ('n', 'no'):
        return False
    raise ValueError('Enter y or n.')


class KeyboardInput:
    """Non-blocking keyboard input handler."""

    def __init__(self):
        """Initialize keyboard input handler."""
        self.fd = sys.stdin.fileno()
        self.old_settings = None

    def __enter__(self):
        """Context manager entry - set up raw mode."""
        self.old_settings = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - restore terminal settings."""
        if self.old_settings:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)
        return False

    def get_key(self, timeout: float = 0.0) -> Optional[str]:
        """
        Get a single keypress with optional timeout.

        Args:
            timeout: Timeout in seconds (0 = non-blocking)

        Returns:
            Key string or None if no key pressed
        """
        # Check if input is available
        if timeout > 0:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None
        else:
            # Non-blocking check
            ready, _, _ = select.select([sys.stdin], [], [], 0)
            if not ready:
                return None

        # Read the key
        ch = sys.stdin.read(1)

        # Handle escape sequences (arrow keys, function keys, etc.)
        if ch == '\x1b':
            # Check if more characters are available (escape sequence)
            ready, _, _ = select.select([sys.stdin], [], [], 0.1)
            if ready:
                ch2 = sys.stdin.read(1)
                if ch2 == '[':
                    # CSI sequence
                    ch3 = sys.stdin.read(1)
                    
                    # Handle sequences that end with ~
                    if ch3 in '0123456789':
                        ch4 = sys.stdin.read(1)
                        if ch4 == '~':
                            return '\x1b[' + ch3 + ch4
                        else:
                            return '\x1b[' + ch3 + ch4
                    else:
                        return '\x1b[' + ch3
                else:
                    return '\x1b' + ch2
            else:
                # Just ESC key
                return '\x1b'

        return ch

    @staticmethod
    def is_ctrl_c(key: str) -> bool:
        """
        Check if key is Ctrl+C.

        Args:
            key: Key string

        Returns:
            True if Ctrl+C, False otherwise
        """
        return key == '\x03'

    @staticmethod
    def key_name(key: str) -> str:
        """
        Get human-readable name for key.

        Args:
            key: Key string

        Returns:
            Human-readable key name
        """
        key_names = {
            '\x1b[A': 'Up',
            '\x1b[B': 'Down',
            '\x1b[C': 'Right',
            '\x1b[D': 'Left',
            '\x1b[H': 'Home',
            '\x1b[F': 'End',
            '\x1b[5~': 'Page Up',
            '\x1b[6~': 'Page Down',
            '\x1b': 'Escape',
            '\r': 'Enter',
            '\n': 'Enter',
            ' ': 'Space',
            '\x03': 'Ctrl+C',
            '\x7f': 'Backspace',
            '\t': 'Tab',
        }
        return key_names.get(key, key if len(key) == 1 else 'Unknown')


class NonBlockingInput:
    """
    Simple non-blocking input reader for use during scanning/attacks.
    Does not require raw mode.
    """

    @staticmethod
    def has_input(timeout: float = 0.0) -> bool:
        """
        Check if input is available.

        Args:
            timeout: Timeout in seconds (0 = non-blocking)

        Returns:
            True if input is available, False otherwise
        """
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        return bool(ready)

    @staticmethod
    def read_line(timeout: float = 0.0) -> Optional[str]:
        """
        Read a line of input with optional timeout.

        Args:
            timeout: Timeout in seconds (0 = non-blocking)

        Returns:
            Input line or None if no input available
        """
        if NonBlockingInput.has_input(timeout):
            try:
                return sys.stdin.readline().strip()
            except (OSError, ValueError):
                return None
        return None


def handle_ctrl_c(func):
    """
    Decorator to handle Ctrl+C gracefully in TUI views.

    Args:
        func: Function to wrap

    Returns:
        Wrapped function
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            # Let the caller handle the interrupt
            raise
    return wrapper


# Convenience functions for common key checks
def is_arrow_key(key: str) -> bool:
    """Check if key is an arrow key."""
    return key in ['\x1b[A', '\x1b[B', '\x1b[C', '\x1b[D']


def is_navigation_key(key: str) -> bool:
    """Check if key is a navigation key (arrows, page up/down, home/end)."""
    return key in ['\x1b[A', '\x1b[B', '\x1b[C', '\x1b[D', 
                   '\x1b[H', '\x1b[F', '\x1b[5~', '\x1b[6~']


def is_enter_key(key: str) -> bool:
    """Check if key is Enter."""
    return key in ['\r', '\n']


def is_escape_key(key: str) -> bool:
    """Check if key is Escape."""
    return key == '\x1b'
