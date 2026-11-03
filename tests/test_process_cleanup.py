import io
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wifite.config import Configuration
from wifite.tools.dnsmasq import Dnsmasq
from wifite.tools.hostapd import Hostapd
from wifite.util.cleanup import CleanupManager
from wifite.util.dragonblood_timing import DragonbloodTimingAttack
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


if __name__ == '__main__':
    unittest.main()
