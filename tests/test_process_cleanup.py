import io
import os
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from wifite.config import Configuration
from wifite.tools.dnsmasq import Dnsmasq
from wifite.tools.hostapd import Hostapd
from wifite.util.cleanup import CleanupManager
from wifite.util.dragonblood_timing import DragonbloodTimingAttack
from wifite.util.process import Process
from wifite.util.wpa3 import WPA3Detector


class StubbornProcess:
    def __init__(self):
        self.force_killed = False
        self.interrupted = False
        self.pid = SimpleNamespace(stdout=io.BytesIO(b''))

    def poll(self):
        return -9 if self.force_killed else None

    def interrupt(self):
        self.interrupted = True

    def force_kill(self):
        self.force_killed = True


class TestProcessCleanup(unittest.TestCase):
    def test_cleanup_manager_uses_force_kill_for_stubborn_process(self):
        process = StubbornProcess()
        manager = CleanupManager()

        with patch('time.sleep'):
            stopped = manager.stop_process(process, 'stubborn')

        self.assertTrue(stopped)
        self.assertTrue(process.force_killed)
        self.assertEqual(manager.cleanup_errors, [])

    def test_hostapd_stop_uses_force_kill_and_marks_service_stopped(self):
        process = StubbornProcess()
        hostapd = Hostapd.__new__(Hostapd)
        hostapd.process = process
        hostapd.running = True

        with patch('wifite.tools.hostapd.time.sleep'):
            hostapd.stop()
        hostapd.cleanup = lambda: None

        self.assertTrue(process.force_killed)
        self.assertFalse(hostapd.running)

    def test_dnsmasq_stop_uses_force_kill_and_marks_service_stopped(self):
        process = StubbornProcess()
        dnsmasq = Dnsmasq.__new__(Dnsmasq)
        dnsmasq.process = process
        dnsmasq.running = True

        with patch('wifite.tools.dnsmasq.time.sleep'):
            dnsmasq.stop()
        dnsmasq.cleanup = lambda: None

        self.assertTrue(process.force_killed)
        self.assertFalse(dnsmasq.running)

    def test_dragonblood_cleanup_uses_force_kill(self):
        process = StubbornProcess()
        attack = DragonbloodTimingAttack.__new__(DragonbloodTimingAttack)
        attack.interface = 'wlan0'
        attack.PROBE_TIMEOUT = 0

        with patch('wifite.util.dragonblood_timing.Process', return_value=process), \
                patch('wifite.util.dragonblood_timing.time.sleep'):
            attack._measure_sae_timing('test.conf')

        self.assertTrue(process.force_killed)

    def test_wpa3_probe_cleanup_uses_force_kill(self):
        process = StubbornProcess()

        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(Configuration, 'temp', return_value=temp_dir + os.sep), \
                patch('wifite.util.process.Process', return_value=process), \
                patch('time.sleep'):
            WPA3Detector._probe_single_sae_group(
                'wlan0', 'AA:BB:CC:DD:EE:FF', 'TestNetwork', 6, 19, 0)

        self.assertTrue(process.force_killed)


class _ExitPid:
    def __init__(self, returncode):
        self.returncode = returncode

    def wait(self):
        return self.returncode


class TestProcessWaitContract(unittest.TestCase):
    def _process(self, returncode):
        process = Process.__new__(Process)
        process.pid = _ExitPid(returncode)
        process.start_time = time.time()
        process.command = ['false']
        return process

    def test_wait_returns_exit_code(self):
        self.assertEqual(self._process(0).wait(), 0)
        self.assertEqual(self._process(3).wait(), 3)

    def test_wait_check_raises_on_nonzero_exit(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self._process(3).wait(check=True)


class TestServiceStartFailureCleanup(unittest.TestCase):
    def test_hostapd_failed_start_restores_interface(self):
        hostapd = Hostapd.__new__(Hostapd)
        hostapd.interface = 'wlan0'
        hostapd.ssid = 'test'
        hostapd.channel = 1
        hostapd.password = None
        hostapd.config_file = '/tmp/does-not-exist.conf'
        hostapd.running = False
        hostapd.process = None

        proc = MagicMock()
        proc.poll.return_value = 1
        proc.stdout.return_value = 'startup failed'

        owner = MagicMock()
        owner.is_managed.return_value = True
        owner.restore_interface.return_value = True

        with patch.object(hostapd, 'create_config_file',
                          return_value='/tmp/does-not-exist.conf'), \
                patch.object(hostapd, '_prepare_interface'), \
                patch('wifite.tools.hostapd.Process', return_value=proc), \
                patch('wifite.tools.hostapd.time.sleep'), \
                patch('wifite.tools.hostapd.os.path.exists', return_value=False), \
                patch.object(Configuration, 'get_interface_manager',
                             return_value=owner), \
                patch('wifite.tools.hostapd.Color'):
            self.assertFalse(hostapd.start())

        owner.restore_interface.assert_called_once_with('wlan0')

    def test_dnsmasq_failed_start_restores_forwarding(self):
        dnsmasq = Dnsmasq.__new__(Dnsmasq)
        dnsmasq.interface = 'wlan0'
        dnsmasq.config_file = '/tmp/does-not-exist.conf'
        dnsmasq.lease_file = None
        dnsmasq.running = False
        dnsmasq.process = None

        proc = MagicMock()
        proc.poll.return_value = 1
        proc.get_output.return_value = ('', 'startup failed')

        owner = MagicMock()
        owner.restore_ip_forwarding.return_value = True

        with patch.object(dnsmasq, 'create_config_file',
                          return_value='/tmp/does-not-exist.conf'), \
                patch.object(dnsmasq, '_setup_routing'), \
                patch('wifite.tools.dnsmasq.Process', return_value=proc), \
                patch('wifite.tools.dnsmasq.time.sleep'), \
                patch('wifite.tools.dnsmasq.os.path.exists', return_value=False), \
                patch.object(Configuration, 'get_interface_manager',
                             return_value=owner), \
                patch('wifite.tools.dnsmasq.Color'):
            self.assertFalse(dnsmasq.start())

        owner.restore_ip_forwarding.assert_called_once()


if __name__ == '__main__':
    unittest.main()
