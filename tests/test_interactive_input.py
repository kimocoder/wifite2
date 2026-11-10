import builtins
import unittest
from unittest.mock import patch

from wifite.attack.all import Answer, AttackAll
from wifite.util.input import interactive_input


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


if __name__ == '__main__':
    unittest.main()
