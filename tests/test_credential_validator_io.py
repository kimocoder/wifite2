import sys
import time
import unittest
from unittest.mock import patch

from wifite.util.credential_validator import CredentialValidator
from wifite.util.process import Process


class TestCredentialValidatorIO(unittest.TestCase):
    def run_validation(self, script, timeout=2):
        validator = CredentialValidator('wlan0', 'AA:BB:CC:DD:EE:FF', 6)
        processes = []
        original_get_output = Process.get_output

        def shortened_get_output(process, timeout=10):
            return original_get_output(process, timeout=0.05)

        def create_process(command, devnull=False):
            process = Process([sys.executable, '-c', script], devnull=False)
            processes.append(process)
            return process

        try:
            with patch('wifite.util.credential_validator.Process', side_effect=create_process), \
                    patch.object(Process, 'get_output', shortened_get_output), \
                    patch.object(validator, '_create_wpa_config', return_value='test.conf'), \
                    patch.object(validator, '_remove_temp_file'), \
                    patch.object(validator, '_apply_rate_limit'):
                return validator.validate_credentials('TestNetwork', 'password123', timeout=timeout)
        finally:
            for process in processes:
                process.cleanup()

    def test_delayed_split_success_marker_does_not_kill_process_early(self):
        script = (
            'import sys, time\n'
            'time.sleep(0.2)\n'
            "sys.stdout.write('CTRL-EVENT-')\n"
            'sys.stdout.flush()\n'
            'time.sleep(0.1)\n'
            "sys.stdout.write('CONNECTED\\n')\n"
            'sys.stdout.flush()\n'
            'time.sleep(30)\n'
        )

        is_valid, _, error_message = self.run_validation(script)

        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    def test_failure_marker_is_read_incrementally(self):
        script = (
            'import sys, time\n'
            'time.sleep(0.2)\n'
            "sys.stdout.write('4-Way Handshake ')\n"
            'sys.stdout.flush()\n'
            'time.sleep(0.1)\n'
            "sys.stdout.write('failed\\n')\n"
            'sys.stdout.flush()\n'
            'time.sleep(30)\n'
        )

        is_valid, _, error_message = self.run_validation(script)

        self.assertFalse(is_valid)
        self.assertEqual(error_message, 'Invalid password')

    def test_timeout_returns_promptly_without_output(self):
        script = 'import time\ntime.sleep(30)\n'

        start = time.monotonic()
        is_valid, _, error_message = self.run_validation(script, timeout=0.15)
        elapsed = time.monotonic() - start

        self.assertFalse(is_valid)
        self.assertEqual(error_message, 'Invalid credentials')
        self.assertLess(elapsed, 2)


if __name__ == '__main__':
    unittest.main()
