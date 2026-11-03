import base64
import struct
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from wifite.tools import nexmon
from wifite.tools.nexmon import (
    CAPABILITY_INJECTION,
    CAPABILITY_MONITOR,
    CAPABILITY_RADIOTAP,
    Nexmon,
    NexmonCapabilities,
    NexmonRefused,
    NexmonUnavailable,
)
from wifite.tools.airmon import Airmon
from wifite.util.interface_manager import InterfaceManager


FULL_CAPS = CAPABILITY_MONITOR | CAPABILITY_RADIOTAP | CAPABILITY_INJECTION


def make_caps(mask=FULL_CAPS, interface='wlan0'):
    return NexmonCapabilities(
        interface=interface,
        driver='brcmfmac',
        mask=mask,
        firmware='7.45.206',
    )


class NexmonTestBase(unittest.TestCase):
    def setUp(self):
        nexmon.reset_cache()
        with nexmon._sessions_lock:
            nexmon._sessions.clear()

    def tearDown(self):
        nexmon.reset_cache()
        with nexmon._sessions_lock:
            nexmon._sessions.clear()


class TestCapabilityDetection(NexmonTestBase):
    def test_query_capability_mask_decodes_little_endian_payload(self):
        payload = base64.b64encode(struct.pack('<i', FULL_CAPS)).decode('ascii')
        result = SimpleNamespace(returncode=0, stdout=payload, stderr='')

        with patch('wifite.tools.nexmon._run', return_value=result):
            self.assertEqual(nexmon._query_capability_mask('wlan0'), FULL_CAPS)

    def test_query_capability_mask_rejects_malformed_payload(self):
        for stdout in ('not-base64!!', base64.b64encode(b'\x01\x02').decode('ascii'),
                       base64.b64encode(struct.pack('<i', FULL_CAPS)).decode('ascii') + 'x'):
            result = SimpleNamespace(returncode=0, stdout=stdout, stderr='')
            with patch('wifite.tools.nexmon._run', return_value=result):
                self.assertIsNone(nexmon._query_capability_mask('wlan0'))

    def test_query_capability_mask_rejects_failed_command(self):
        result = SimpleNamespace(returncode=1, stdout='', stderr='denied')
        with patch('wifite.tools.nexmon._run', return_value=result):
            self.assertIsNone(nexmon._query_capability_mask('wlan0'))

    def test_probe_ignores_non_brcmfmac_driver(self):
        with patch('wifite.tools.nexmon._read_driver', return_value='iwlwifi'):
            self.assertIsNone(nexmon.probe('wlan0'))

    def test_probe_fails_closed_for_zero_mask(self):
        with patch('wifite.tools.nexmon._read_driver', return_value='brcmfmac'), \
                patch('wifite.tools.nexmon._query_capability_mask', return_value=0):
            self.assertIsNone(nexmon.probe('wlan0'))

    def test_probe_rejects_invalid_interface_name(self):
        self.assertIsNone(nexmon.probe('bad name!'))

    def test_probe_caches_results_until_invalidated(self):
        with patch('wifite.tools.nexmon._ifindex', return_value=3), \
                patch('wifite.tools.nexmon._probe_uncached',
                      return_value=make_caps()) as uncached:
            self.assertIsNotNone(nexmon.probe('wlan0'))
            self.assertIsNotNone(nexmon.probe('wlan0'))
            self.assertEqual(uncached.call_count, 1)

            Nexmon.invalidate_cache('wlan0')
            nexmon.probe('wlan0')
            self.assertEqual(uncached.call_count, 2)

    def test_system_applicable_detects_brcmfmac_netdev(self):
        with patch('os.listdir', return_value=['lo', 'wlan0']), \
                patch('os.readlink', side_effect=lambda path: '/drivers/brcmfmac'
                      if 'wlan0' in path else '/drivers/virtual'):
            self.assertTrue(nexmon.system_applicable())

    def test_system_applicable_false_without_brcmfmac(self):
        with patch('os.listdir', return_value=['lo', 'eth0']), \
                patch('os.readlink', side_effect=OSError):
            self.assertFalse(nexmon.system_applicable())


class TestMonitorLifecycle(NexmonTestBase):
    def test_start_rejects_interface_without_capabilities(self):
        with patch('wifite.tools.nexmon.probe', return_value=None):
            with self.assertRaises(NexmonUnavailable):
                nexmon.start_monitor('wlan0')

    def test_start_rejects_capabilities_without_radiotap(self):
        with patch('wifite.tools.nexmon.probe',
                   return_value=make_caps(CAPABILITY_MONITOR | CAPABILITY_INJECTION)):
            with self.assertRaises(NexmonUnavailable):
                nexmon.start_monitor('wlan0')

    def test_start_rejects_non_managed_mode(self):
        with patch('wifite.tools.nexmon.probe', return_value=make_caps()), \
                patch('wifite.tools.nexmon._interface_mode', return_value='AP'):
            with self.assertRaises(NexmonRefused):
                nexmon.start_monitor('wlan0')

    def test_start_refuses_associated_interface(self):
        with patch('wifite.tools.nexmon.probe', return_value=make_caps()), \
                patch('wifite.tools.nexmon._interface_mode', return_value='managed'), \
                patch('wifite.tools.nexmon._read_phy', return_value='phy0'), \
                patch('wifite.tools.nexmon._assert_safe_to_take_over',
                      side_effect=NexmonRefused('wlan0 is associated')):
            with self.assertRaises(NexmonRefused):
                nexmon.start_monitor('wlan0')
        self.assertFalse(Nexmon.has_session('wlan0'))

    @contextmanager
    def _owned_monitor(self, delete_interface):
        """Run start_monitor with all system probing mocked and keep it mocked."""
        deleted = []
        modes = {'wlan0': 'managed', 'wlan0mon': 'monitor'}

        def fake_delete(name):
            deleted.append(name)
            return delete_interface(name)

        with patch('wifite.tools.nexmon.probe', return_value=make_caps()), \
                patch('wifite.tools.nexmon._interface_mode',
                      side_effect=lambda name: modes.get(name)), \
                patch('wifite.tools.nexmon._read_phy', return_value='phy0'), \
                patch('wifite.tools.nexmon._assert_safe_to_take_over'), \
                patch('wifite.tools.nexmon._select_monitor_name',
                      return_value='wlan0mon'), \
                patch('wifite.tools.nexmon._is_up', return_value=False), \
                patch('wifite.tools.nexmon._power_save_state', return_value=False), \
                patch('wifite.tools.nexmon._create_monitor'), \
                patch('wifite.tools.nexmon._ifindex',
                      side_effect=lambda name: 42 if name == 'wlan0mon' else None), \
                patch('wifite.tools.nexmon._run_ok', return_value=True), \
                patch('wifite.tools.nexmon._radiotap_monitor_mode', return_value=2), \
                patch('wifite.tools.nexmon._delete_interface', side_effect=fake_delete):
            yield nexmon.start_monitor('wlan0'), deleted

    def test_start_and_stop_restore_station(self):
        with self._owned_monitor(lambda name: True) as (monitor, deleted):
            self.assertEqual(monitor, 'wlan0mon')
            self.assertTrue(Nexmon.has_session('wlan0'))
            self.assertTrue(Nexmon.has_session('wlan0mon'))

            self.assertTrue(Nexmon.stop('wlan0mon'))
            self.assertEqual(deleted, ['wlan0mon'])

        self.assertFalse(Nexmon.has_session('wlan0'))
        self.assertFalse(Nexmon.has_session('wlan0mon'))

    def test_stop_is_idempotent(self):
        with self._owned_monitor(lambda name: True):
            self.assertTrue(Nexmon.stop('wlan0mon'))
            self.assertFalse(Nexmon.stop('wlan0mon'))

    def test_cleanup_all_is_idempotent(self):
        with self._owned_monitor(lambda name: True):
            self.assertEqual(Nexmon.cleanup_all(), ['wlan0'])
            self.assertEqual(Nexmon.cleanup_all(), [])
            self.assertFalse(Nexmon.has_session('wlan0'))

    def test_stop_leaves_foreign_monitor_untouched(self):
        session = SimpleNamespace(
            station='wlan0', monitor='wlan0mon', owned=False, active=True,
        )
        nexmon._register_session(session)
        deleted = []

        with patch('wifite.tools.nexmon._delete_interface',
                   side_effect=lambda name: deleted.append(name) or True):
            self.assertTrue(Nexmon.stop('wlan0mon'))

        self.assertEqual(deleted, [])
        self.assertFalse(Nexmon.has_session('wlan0'))

    def test_failed_rollback_keeps_session_for_retry(self):
        errors = ['failed to delete monitor interface wlan0mon']
        with patch('wifite.tools.nexmon.probe', return_value=make_caps()), \
                patch('wifite.tools.nexmon._interface_mode', return_value='managed'), \
                patch('wifite.tools.nexmon._read_phy', return_value='phy0'), \
                patch('wifite.tools.nexmon._assert_safe_to_take_over'), \
                patch('wifite.tools.nexmon._select_monitor_name', return_value='wlan0mon'), \
                patch('wifite.tools.nexmon._is_up', return_value=False), \
                patch('wifite.tools.nexmon._power_save_state', return_value=False), \
                patch('wifite.tools.nexmon._create_monitor'), \
                patch('wifite.tools.nexmon._ifindex', return_value=None), \
                patch('wifite.tools.nexmon._run_ok', return_value=True), \
                patch('wifite.tools.nexmon._radiotap_monitor_mode', return_value=2), \
                patch('wifite.tools.nexmon._restore_session', return_value=errors):
            with self.assertRaises(Exception):
                nexmon.start_monitor('wlan0')

        self.assertTrue(Nexmon.has_session('wlan0'))


class TestInterfaceManagerIntegration(NexmonTestBase):
    def test_check_injection_support_uses_nexmon_capability_bit(self):
        with patch.object(InterfaceManager, '_get_interface_driver',
                          return_value='brcmfmac'), \
                patch.object(Nexmon, 'probe', return_value=make_caps(FULL_CAPS)):
            self.assertTrue(InterfaceManager.check_injection_support('wlan0'))

        with patch.object(InterfaceManager, '_get_interface_driver',
                          return_value='brcmfmac'), \
                patch.object(Nexmon, 'probe',
                             return_value=make_caps(CAPABILITY_MONITOR | CAPABILITY_RADIOTAP)):
            self.assertFalse(InterfaceManager.check_injection_support('wlan0'))

    def test_check_injection_support_fails_closed_without_nexmon(self):
        with patch.object(InterfaceManager, '_get_interface_driver',
                          return_value='brcmfmac'), \
                patch.object(Nexmon, 'probe', return_value=None):
            self.assertFalse(InterfaceManager.check_injection_support('wlan0'))

    def test_check_monitor_support_requires_monitor_and_radiotap(self):
        with patch.object(InterfaceManager, '_get_interface_mode', return_value='managed'), \
                patch.object(InterfaceManager, '_get_interface_driver',
                             return_value='brcmfmac'), \
                patch.object(Nexmon, 'probe', return_value=make_caps(FULL_CAPS)):
            self.assertTrue(InterfaceManager.check_monitor_mode_support('wlan0'))

        with patch.object(InterfaceManager, '_get_interface_mode', return_value='managed'), \
                patch.object(InterfaceManager, '_get_interface_driver',
                             return_value='brcmfmac'), \
                patch.object(Nexmon, 'probe',
                             return_value=make_caps(CAPABILITY_MONITOR)):
            self.assertFalse(InterfaceManager.check_monitor_mode_support('wlan0'))


class TestAirmonIntegration(NexmonTestBase):
    def setUp(self):
        super().setUp()
        self._use_ipiw = Airmon.use_ipiw
        Airmon.use_ipiw = False

    def tearDown(self):
        Airmon.use_ipiw = self._use_ipiw
        super().tearDown()

    def test_start_uses_nexmon_for_brcmfmac(self):
        adapter = SimpleNamespace(interface='wlan0', driver='brcmfmac')

        with patch.object(Airmon, 'get_iface_info', return_value=adapter), \
                patch.object(Nexmon, 'probe', return_value=make_caps()), \
                patch.object(Nexmon, 'start_monitor', return_value='wlan0mon') as start, \
                patch('wifite.tools.airmon.Color'):
            self.assertEqual(Airmon.start('wlan0'), 'wlan0mon')

        start.assert_called_once_with('wlan0')
        self.assertTrue(Airmon.use_ipiw)

    def test_start_keeps_legacy_path_without_nexmon(self):
        adapter = SimpleNamespace(interface='wlan0', driver='brcmfmac')

        with patch.object(Airmon, 'get_iface_info', return_value=adapter), \
                patch.object(Nexmon, 'probe', return_value=None), \
                patch('wifite.tools.airmon.Color'), \
                patch('wifite.tools.airmon.Iw.is_monitor', return_value=True), \
                patch.object(Airmon, 'start_monitor', return_value='wlan0mon') as legacy:
            self.assertEqual(Airmon.start('wlan0'), 'wlan0mon')

        legacy.assert_called_once_with('wlan0')

    def test_stop_delegates_to_nexmon_session(self):
        with patch.object(Nexmon, 'has_session', return_value=True), \
                patch.object(Nexmon, 'stop', return_value=True) as stop, \
                patch('wifite.tools.airmon.Color'):
            self.assertEqual(Airmon.stop('wlan0mon'), ('wlan0mon', 'wlan0mon'))

        stop.assert_called_once_with('wlan0mon')


if __name__ == '__main__':
    unittest.main()