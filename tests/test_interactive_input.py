import builtins
from contextlib import redirect_stdout
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wifite.attack.all import Answer, AttackAll
from wifite.config import Configuration
from wifite.util.input import (
    interactive_input,
    parse_index_selection,
    parse_yes_no,
    prompt_until_valid,
)


def stdin_eof():
    raise EOFError('eof')


class TestInteractiveInput(unittest.TestCase):
    def test_passthrough_when_stdin_available(self):
        with patch.object(builtins, 'input', return_value='  yes  '):
            self.assertEqual(interactive_input(), '  yes  ')

    def test_eof_raises_keyboard_interrupt_with_notice(self):
        with patch.object(builtins, 'input', side_effect=stdin_eof):
            with self.assertRaises(KeyboardInterrupt):
                interactive_input()

    def test_prompt_site_exits_gracefully_on_eof(self):
        # Regression test: closed stdin at an interactive prompt used to
        # crash with "Unexpected Error: EOF when reading a line".
        with patch.object(builtins, 'input', side_effect=stdin_eof):
            answer = AttackAll.user_wants_to_continue(targets_remaining=1,
                                                      attacks_remaining=1)
        self.assertEqual(answer, Answer.ExitOrReturn)

    def test_yes_no_parser_requires_explicit_choice_or_uses_default(self):
        self.assertTrue(parse_yes_no(' YES '))
        self.assertFalse(parse_yes_no('no'))
        self.assertTrue(parse_yes_no('', default=True))
        self.assertFalse(parse_yes_no('', default=False))
        with self.assertRaises(ValueError):
            parse_yes_no('maybe')

    def test_index_selection_parser_checks_all_indices_and_ranges(self):
        self.assertEqual(parse_index_selection('1, 3-4', 4), [0, 2, 3])
        self.assertEqual(parse_index_selection('6-10-11-12', 12), [5, 9, 10, 11])
        self.assertEqual(parse_index_selection('all', 3), [0, 1, 2])
        for answer in ('', '0', '4', '2-1', '1,,2', 'one'):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                parse_index_selection(answer, 3)

    def test_invalid_input_shows_message_then_redraws_prompt(self):
        class TTYOutput(io.StringIO):
            def isatty(self):
                return True

        def parse_yes_no_or_retry(value):
            value = value.strip().lower()
            if value in ('y', 'yes'):
                return True
            if value in ('n', 'no'):
                return False
            raise ValueError()

        output = TTYOutput()
        with patch('wifite.util.input.sys.stdout', output), \
                patch('wifite.util.input.shutil.get_terminal_size',
                      return_value=SimpleNamespace(columns=40)), \
                patch('wifite.util.input.interactive_input', side_effect=['', 'Y']), \
                patch('time.sleep') as sleep:
            result = prompt_until_valid(
                'Restore interface to managed mode?' + (' details' * 8)
                + '\n    Confirm (y/n): ',
                parse_yes_no_or_retry,
                invalid_message='Please enter y or n.')

        self.assertTrue(result)
        self.assertEqual(sleep.call_count, 1)
        rendered = output.getvalue()
        self.assertIn('Please enter y or n.', rendered)
        self.assertEqual(rendered.count('Restore interface to managed mode?'), 2)
        self.assertIn('\033[4A', rendered)
        self.assertGreaterEqual(rendered.count('\r\033[2K'), 5)

    def test_attack_continue_prompt_is_emitted_once(self):
        output = io.StringIO()
        with patch('wifite.util.input.interactive_input', return_value='c'), \
                patch.object(Configuration, 'infinite_mode', False), \
                redirect_stdout(output):
            answer = AttackAll.user_wants_to_continue(
                targets_remaining=0, attacks_remaining=1)

        self.assertEqual(answer, Answer.Continue)
        rendered = output.getvalue()
        self.assertEqual(rendered.count('Do you want to'), 1)
        self.assertIn('current target,\n    or ', rendered)


if __name__ == '__main__':
    unittest.main()
