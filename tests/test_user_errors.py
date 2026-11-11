"""User-fixable failures must not read like crashes."""

import unittest
from contextlib import ExitStack
from unittest.mock import patch

from wifite.config import Configuration
from wifite.util.errors import WifiteError
from wifite.wifite import main


class TestUserErrors(unittest.TestCase):

    def invoke_main(self, start_error):
        with ExitStack() as stack:
            wifite_class = stack.enter_context(patch('wifite.wifite.Wifite'))
            stack.enter_context(patch('wifite.wifite.Configuration.exit_gracefully'))
            stack.enter_context(patch.object(Configuration, 'interface_manager', None, create=True))
            stack.enter_context(patch('wifite.util.process.ProcessManager'))
            stack.enter_context(patch('subprocess.run'))
            stack.enter_context(patch('signal.signal'))
            pexception = stack.enter_context(patch('wifite.wifite.Color.pexception'))
            wifite_class.return_value.start.side_effect = start_error

            with self.assertRaises(SystemExit) as caught:
                main()

        return caught.exception.code, pexception

    def test_wifite_error_prints_message_without_traceback(self):
        code, pexception = self.invoke_main(
            WifiteError('failed to enable monitor mode'))

        self.assertEqual(code, 1)
        pexception.assert_not_called()

    def test_unexpected_exception_still_prints_traceback(self):
        code, pexception = self.invoke_main(RuntimeError('boom'))

        self.assertEqual(code, 1)
        pexception.assert_called_once()


if __name__ == '__main__':
    unittest.main()