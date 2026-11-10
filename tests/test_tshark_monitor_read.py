import os
import time
import unittest

from wifite.tools.tshark import TsharkMonitor


class _FakePopen:
    def __init__(self):
        self._read_fd, self._write_fd = os.pipe()
        self.stdout = os.fdopen(self._read_fd, 'rb', buffering=0)
        self.write_handle = os.fdopen(self._write_fd, 'wb', buffering=0)

    def write_line(self, data):
        self.write_handle.write(data)
        self.write_handle.flush()

    def close(self):
        for handle in (self.stdout, self.write_handle):
            try:
                handle.close()
            except OSError:
                pass


class _FakeProcess:
    def __init__(self):
        self.pid = _FakePopen()


def make_monitor():
    monitor = TsharkMonitor('wlan0')
    monitor.proc = _FakeProcess()
    return monitor


class TestTsharkMonitorReadFrame(unittest.TestCase):
    def setUp(self):
        self.monitor = make_monitor()

    def tearDown(self):
        self.monitor.proc.pid.close()

    def test_read_frame_returns_none_promptly_when_idle(self):
        # Regression test: read_frame used to block in readline() on an
        # idle channel, which prevented --monitor-duration from firing.
        started = time.monotonic()
        result = self.monitor.read_frame(timeout=0.2)
        elapsed = time.monotonic() - started

        self.assertIsNone(result)
        self.assertLess(elapsed, 1.0)

    def test_read_frame_parses_frame_line(self):
        self.monitor.proc.pid.write_line(
            b'1794337957.123\t0x0c\tAA:BB:CC:DD:EE:FF\t11:22:33:44:55:66\tAA:BB:CC:DD:EE:FF\t6\n'
        )

        result = self.monitor.read_frame(timeout=1.0)

        self.assertIsNotNone(result)
        self.assertEqual(result['timestamp'], 1794337957.123)
        self.assertEqual(result['frame_type'], '0x0c')
        self.assertEqual(result['source_mac'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(result['dest_mac'], '11:22:33:44:55:66')
        self.assertEqual(result['bssid'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(result['channel'], '6')

    def test_read_frame_returns_none_for_short_lines(self):
        self.monitor.proc.pid.write_line(b'only\tthree\tfields\n')

        result = self.monitor.read_frame(timeout=1.0)

        self.assertIsNone(result)

    def test_read_frame_returns_none_without_process(self):
        monitor = TsharkMonitor('wlan0')
        self.assertIsNone(monitor.read_frame(timeout=0.1))


if __name__ == '__main__':
    unittest.main()
