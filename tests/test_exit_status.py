import signal
import subprocess
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from wifite.config import Configuration
from wifite.wifite import emergency_exit, main, sigterm_handler


class TestExitStatus(unittest.TestCase):
    def invoke_main(self, constructor_error=None, start_error=None):
        with ExitStack() as stack:
            wifite_class = stack.enter_context(patch('wifite.wifite.Wifite'))
            stack.enter_context(patch('wifite.wifite.Configuration.exit_gracefully'))
            stack.enter_context(patch.object(Configuration, 'interface_manager', None, create=True))
            stack.enter_context(patch('wifite.util.process.ProcessManager'))
            stack.enter_context(patch('subprocess.run'))
            stack.enter_context(patch('signal.signal'))
            stack.enter_context(patch('wifite.wifite.Color.pl'))
            stack.enter_context(patch('wifite.wifite.Color.pexception'))

            if constructor_error is not None:
                wifite_class.side_effect = constructor_error
            else:
                wifite_class.return_value.start.side_effect = start_error

            with self.assertRaises(SystemExit) as caught:
                main()

        return caught.exception.code

    def test_successful_execution_exits_zero(self):
        self.assertEqual(self.invoke_main(), 0)

    def test_explicit_system_exit_code_is_preserved(self):
        self.assertEqual(self.invoke_main(constructor_error=SystemExit(2)), 2)

    def test_non_integer_system_exit_is_failure(self):
        self.assertEqual(self.invoke_main(constructor_error=SystemExit('invalid arguments')), 1)

    def test_sigterm_handler_raises_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            sigterm_handler(signal.SIGTERM, None)

    def test_main_installs_sigterm_handler(self):
        with ExitStack() as stack:
            stack.enter_context(patch('wifite.wifite.Wifite'))
            stack.enter_context(patch('wifite.wifite.Configuration.exit_gracefully'))
            stack.enter_context(patch.object(Configuration, 'interface_manager', None, create=True))
            stack.enter_context(patch('wifite.util.process.ProcessManager'))
            stack.enter_context(patch('subprocess.run'))
            signal_mock = stack.enter_context(patch('signal.signal'))

            with self.assertRaises(SystemExit):
                main()

        sigterm_installs = [args[1] for args, _ in signal_mock.call_args_list
                            if len(args) >= 2 and args[0] == signal.SIGTERM]
        # First install routes SIGTERM through the Ctrl+C cleanup path;
        # the finally phase later escalates it to an emergency hard exit.
        self.assertIs(sigterm_installs[0], sigterm_handler)
        self.assertIn(emergency_exit, sigterm_installs)

    def test_failures_exit_nonzero(self):
        failures = [
            OSError('system failure'),
            subprocess.CalledProcessError(1, ['tool']),
            PermissionError('permission denied'),
            RuntimeError('unexpected failure'),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.assertEqual(self.invoke_main(start_error=failure), 1)

    def test_keyboard_interrupt_uses_conventional_exit_status(self):
        self.assertEqual(self.invoke_main(start_error=KeyboardInterrupt()), 130)

    def test_non_root_execution_exits_nonzero(self):
        from wifite.wifite import Wifite

        with ExitStack() as stack:
            stack.enter_context(patch('wifite.wifite.Configuration.initialize'))
            stack.enter_context(patch('wifite.util.output.OutputManager.initialize'))
            stack.enter_context(patch('wifite.wifite.os.getuid', return_value=1000))
            stack.enter_context(patch.object(Configuration, 'syscheck', False, create=True))
            stack.enter_context(patch.object(Configuration, 'use_tui', False, create=True))
            stack.enter_context(patch('wifite.wifite.Configuration.exit_gracefully', side_effect=SystemExit(0)))
            stack.enter_context(patch('wifite.wifite.Color.pl'))

            with self.assertRaises(SystemExit) as caught:
                Wifite()

        self.assertEqual(caught.exception.code, 1)

    def test_invalid_interface_configuration_exits_nonzero(self):
        from wifite.wifite import Wifite

        with ExitStack() as stack:
            stack.enter_context(patch.object(Wifite, 'detect_and_assign_interfaces'))
            stack.enter_context(patch.object(Wifite, 'validate_interface_assignment', return_value=(False, 'invalid', [])))
            stack.enter_context(patch.object(Wifite, 'display_validation_results'))
            stack.enter_context(patch('wifite.wifite.Configuration.exit_gracefully', side_effect=SystemExit(0)))
            stack.enter_context(patch('wifite.wifite.Color.pl'))

            with self.assertRaises(SystemExit) as caught:
                Wifite.__new__(Wifite).scan_and_attack()

        self.assertEqual(caught.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
