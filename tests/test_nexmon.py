import base64
import contextlib
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

        # Nexmon delegates station link changes to the interface owner. Use a
        # stub so unit tests never touch the host's real radios.
        class _OwnerStub:
            def claim_interface(self, interface):
                return True

            def set_interface_up(self, interface, up):
                return True

        self._owner_patcher = patch(
            'wifite.config.Configuration.get_interface_manager',
            return_value=_OwnerStub())
        self._owner_patcher.start()

    def tearDown(self):
        self._owner_patcher.stop()
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

    def _hexdump_line(self, offset, *bytes_):
        fields = ''.join(f'{b:02x} ' for b in bytes_)[:3 * 16]
        fields += '   ' * (16 - len(bytes_))
        ascii_column = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bytes_)
        ascii_column += ' ' * (16 - len(ascii_column))
        return f'0x{offset:06x}: {fields}{ascii_column}'

    def test_parse_hexdump_decodes_nexutil_format(self):
        line = self._hexdump_line(0, 7, 0, 0, 0)
        self.assertEqual(
            nexmon._parse_hexdump(line + '\n'),
            b'\x07\x00\x00\x00',
        )

    def test_parse_hexdump_ignores_ascii_column(self):
        # ASCII letters must not be mistaken for hex data bytes.
        line = self._hexdump_line(0, 0x61, 0x62, 0, 0)
        self.assertEqual(
            nexmon._parse_hexdump(line + '\n'),
            b'\x61\x62\x00\x00',
        )

    def test_parse_hexdump_spans_multiple_lines(self):
        text = (
            self._hexdump_line(0, *range(16)) + '\n'
            + self._hexdump_line(16, 0x07, 0, 0, 0) + '\n'
        )
        self.assertEqual(len(nexmon._parse_hexdump(text)), 20)

    def test_parse_hexdump_rejects_garbage(self):
        self.assertIsNone(nexmon._parse_hexdump('invalid string'))
        self.assertIsNone(nexmon._parse_hexdump(''))

    def test_query_capability_mask_falls_back_to_hexdump(self):
        hexdump = self._hexdump_line(0, 7, 0, 0, 0) + '\n'
        results = [
            SimpleNamespace(returncode=0, stdout='not-base64!!', stderr=''),
            SimpleNamespace(returncode=0, stdout=hexdump, stderr=''),
        ]
        with patch('wifite.tools.nexmon._run', side_effect=results) as run:
            self.assertEqual(nexmon._query_capability_mask('wlan0'), FULL_CAPS)
        self.assertEqual(run.call_count, 2)
        self.assertIn('-R', run.call_args_list[0][0][0])
        self.assertNotIn('-R', run.call_args_list[1][0][0])

    def test_query_capability_mask_falls_back_when_r_option_rejected(self):
        hexdump = self._hexdump_line(0, 7, 0, 0, 0) + '\n'
        results = [
            SimpleNamespace(returncode=1, stdout='', stderr='unrecognized option'),
            SimpleNamespace(returncode=0, stdout=hexdump, stderr=''),
        ]
        with patch('wifite.tools.nexmon._run', side_effect=results) as run:
            self.assertEqual(nexmon._query_capability_mask('wlan0'), FULL_CAPS)
        self.assertEqual(run.call_count, 2)

    def test_query_capability_mask_skips_fallback_when_tool_missing(self):
        with patch('wifite.tools.nexmon._run', return_value=None) as run:
            self.assertIsNone(nexmon._query_capability_mask('wlan0'))
        self.assertEqual(run.call_count, 1)

    def test_probe_ignores_non_brcmfmac_driver(self):
        with patch('wifite.tools.nexmon._read_driver', return_value='iwlwifi'):
            self.assertIsNone(nexmon.probe('wlan0'))

    def test_probe_fails_closed_for_zero_mask(self):
        with patch('wifite.tools.nexmon._read_driver', return_value='brcmfmac'), \
                patch('wifite.tools.nexmon._query_capability_mask', return_value=0):
            self.assertIsNone(nexmon.probe('wlan0'))

    def test_firmware_version_parses_revinfo(self):
        revinfo = (
            'firmware 7.45.265 (28bca26 CY nexmon.org: 7a89f-dirty-4) FWID 01-b677b91b\n'
            'vendorid 0x14e4\n'
            'chipnum 0x4345\n'
            'platform             | firmware                         | vendorid\n'
        )
        result = SimpleNamespace(returncode=0, stdout=revinfo, stderr='')
        with patch('wifite.tools.nexmon._run', return_value=result):
            self.assertEqual(
                nexmon._firmware_version('wlan0'),
                '7.45.265 (28bca26 CY nexmon.org: 7a89f-dirty-4) FWID 01-b677b91b',
            )

    def test_firmware_version_fails_closed(self):
        for stdout in ('', 'vendorid 0x14e4\n', 'firmware\n'):
            result = SimpleNamespace(returncode=0, stdout=stdout, stderr='')
            with patch('wifite.tools.nexmon._run', return_value=result):
                self.assertIsNone(nexmon._firmware_version('wlan0'), stdout)
        result = SimpleNamespace(returncode=1, stdout='', stderr='denied')
        with patch('wifite.tools.nexmon._run', return_value=result):
            self.assertIsNone(nexmon._firmware_version('wlan0'))
        with patch('wifite.tools.nexmon._run', return_value=None):
            self.assertIsNone(nexmon._firmware_version('wlan0'))

    def test_probe_reports_firmware_from_revinfo(self):
        with patch('wifite.tools.nexmon._read_driver', return_value='brcmfmac'), \
                patch('wifite.tools.nexmon._query_capability_mask', return_value=FULL_CAPS), \
                patch('wifite.tools.nexmon._firmware_version',
                      return_value='7.45.265 (28bca26 CY nexmon.org: 7a89f-dirty-4)'):
            caps = nexmon.probe('wlan0', use_cache=False)
        self.assertEqual(caps.firmware,
                         '7.45.265 (28bca26 CY nexmon.org: 7a89f-dirty-4)')
        self.assertIn('7.45.265', caps.describe())

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
                patch('wifite.tools.nexmon._sweep_leaked_monitor', return_value=None), \
                patch('wifite.tools.nexmon._is_associated', return_value=False), \
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


class TestMonitorReuse(NexmonTestBase):
    def _reuse_mocks(self, state):
        """Monitor vif reuse: reset to managed, then the full lifecycle."""
        ifindexes = {'wlan0': 3}

        def fake_create(station, phy, monitor):
            ifindexes[monitor] = 42

        def fake_delete(name):
            ifindexes.pop(name, None)
            return True

        def fake_mode(name):
            if name == 'wlan0':
                return 'managed' if state.get('reset') else 'monitor'
            return 'monitor'

        def fake_run_ok(cmd, timeout=5):
            if cmd[:4] == ['iw', 'dev', 'wlan0', 'set']:
                state['reset'] = True
            return True

        return [
            patch('wifite.tools.nexmon.probe', return_value=make_caps()),
            patch('wifite.tools.nexmon._interface_mode', side_effect=fake_mode),
            patch('wifite.tools.nexmon._read_phy', return_value='phy0'),
            patch('wifite.tools.nexmon._assert_safe_to_take_over'),
            patch('wifite.tools.nexmon._sweep_leaked_monitor', return_value=None),
            patch('wifite.tools.nexmon._is_associated', return_value=False),
            patch('wifite.tools.nexmon._is_up', return_value=False),
            patch('wifite.tools.nexmon._power_save_state', return_value=False),
            patch('wifite.tools.nexmon._create_monitor', side_effect=fake_create),
            patch('wifite.tools.nexmon._ifindex',
                  side_effect=lambda n: ifindexes.get(n)),
            patch('wifite.tools.nexmon._run_ok', side_effect=fake_run_ok),
            patch('wifite.tools.nexmon._radiotap_monitor_mode', return_value=2),
            patch('wifite.tools.nexmon._delete_interface', side_effect=fake_delete),
        ]

    def test_monitor_interface_is_reset_and_rebuilt(self):
        state = {}
        with contextlib.ExitStack() as stack:
            for m in self._reuse_mocks(state):
                stack.enter_context(m)
            monitor = nexmon.start_monitor('wlan0')
        self.assertEqual(monitor, 'wlan0mon')
        self.assertTrue(state.get('reset'), 'station vif was not reset to managed')
        self.assertTrue(Nexmon.has_session('wlan0mon'))

    def test_monitor_reset_failure_fails_closed(self):
        with patch('wifite.tools.nexmon.probe', return_value=make_caps()), \
                patch('wifite.tools.nexmon._interface_mode', return_value='monitor'), \
                patch('wifite.tools.nexmon._run_ok', return_value=False):
            with self.assertRaises(nexmon.NexmonError):
                nexmon.start_monitor('wlan0')
        self.assertFalse(Nexmon.has_session('wlan0'))


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

    def test_ask_ensures_radiotap_on_brcmfmac_monitor(self):
        with patch.object(Airmon, 'terminate_conflicting_processes'), \
                patch('wifite.tools.airmon.Iw.get_interfaces',
                      return_value=['wlan0mon']), \
                patch.object(Airmon, 'get_iface_info',
                             return_value=SimpleNamespace(driver='brcmfmac')), \
                patch.object(Nexmon, 'probe', return_value=make_caps()), \
                patch.object(Nexmon, 'start_monitor', return_value='wlan0mon') as start, \
                patch('wifite.tools.airmon.Color'):
            self.assertEqual(Airmon.ask(), 'wlan0mon')
        start.assert_called_once_with('wlan0mon')
        self.assertIsNone(Airmon.base_interface)

    def test_ask_non_brcmfmac_monitor_shortcut_unchanged(self):
        with patch.object(Airmon, 'terminate_conflicting_processes'), \
                patch('wifite.tools.airmon.Iw.get_interfaces',
                      return_value=['wlan0mon']), \
                patch.object(Airmon, 'get_iface_info',
                             return_value=SimpleNamespace(driver='mt76x0u')), \
                patch.object(Airmon, 'start') as start, \
                patch('wifite.tools.airmon.Color'):
            self.assertEqual(Airmon.ask(), 'wlan0mon')
        start.assert_not_called()

    def test_stop_delegates_to_nexmon_session(self):
        with patch.object(Nexmon, 'has_session', return_value=True), \
                patch.object(Nexmon, 'stop', return_value=True) as stop, \
                patch('wifite.tools.airmon.Color'):
            self.assertEqual(Airmon.stop('wlan0mon'), ('wlan0mon', 'wlan0mon'))

        stop.assert_called_once_with('wlan0mon')


class TestLeakedMonitorSweep(NexmonTestBase):
    def _sweep_mocks(self, deleted, ifindexes=None, station_up=False,
                     monitor_phy='phy0', monitor_mode='monitor'):
        if ifindexes is None:
            ifindexes = {'wlan0': 3, 'wlan0mon': 42}
        modes = {'wlan0': 'managed', 'wlan0mon': monitor_mode}
        return [
            patch('wifite.tools.nexmon._ifindex',
                  side_effect=lambda n: ifindexes.get(n)),
            patch('wifite.tools.nexmon._read_phy', return_value=monitor_phy),
            patch('wifite.tools.nexmon._interface_mode',
                  side_effect=lambda n: modes.get(n)),
            patch('wifite.tools.nexmon._is_up', return_value=station_up),
            patch('wifite.tools.nexmon._delete_interface',
                  side_effect=lambda n: deleted.append(n) or True),
        ]

    def test_sweep_removes_leaked_monitor(self):
        deleted = []
        with contextlib.ExitStack() as stack:
            for m in self._sweep_mocks(deleted, station_up=False):
                stack.enter_context(m)
            self.assertEqual(nexmon._sweep_leaked_monitor('wlan0', 'phy0'), 'wlan0mon')
        self.assertEqual(deleted, ['wlan0mon'])

    def test_sweep_keeps_monitor_when_station_is_up(self):
        deleted = []
        with contextlib.ExitStack() as stack:
            for m in self._sweep_mocks(deleted, station_up=True):
                stack.enter_context(m)
            self.assertIsNone(nexmon._sweep_leaked_monitor('wlan0', 'phy0'))
        self.assertEqual(deleted, [])

    def test_sweep_keeps_monitor_from_live_session(self):
        session = SimpleNamespace(
            station='wlan0', monitor='wlan0mon', owned=True, active=True)
        nexmon._register_session(session)
        deleted = []
        with contextlib.ExitStack() as stack:
            for m in self._sweep_mocks(deleted, station_up=False):
                stack.enter_context(m)
            self.assertIsNone(nexmon._sweep_leaked_monitor('wlan0', 'phy0'))
        self.assertEqual(deleted, [])

    def test_sweep_ignores_monitor_on_other_phy(self):
        deleted = []
        with contextlib.ExitStack() as stack:
            for m in self._sweep_mocks(deleted, station_up=False,
                                       monitor_phy='phy9'):
                stack.enter_context(m)
            self.assertIsNone(nexmon._sweep_leaked_monitor('wlan0', 'phy0'))
        self.assertEqual(deleted, [])

    def test_sweep_ignores_non_monitor_interface(self):
        deleted = []
        with contextlib.ExitStack() as stack:
            for m in self._sweep_mocks(deleted, station_up=False,
                                       monitor_mode='managed'):
                stack.enter_context(m)
            self.assertIsNone(nexmon._sweep_leaked_monitor('wlan0', 'phy0'))
        self.assertEqual(deleted, [])

    def test_sweep_ignores_missing_interface(self):
        deleted = []
        with contextlib.ExitStack() as stack:
            for m in self._sweep_mocks(deleted, station_up=False,
                                       ifindexes={'wlan0': 3}):
                stack.enter_context(m)
            self.assertIsNone(nexmon._sweep_leaked_monitor('wlan0', 'phy0'))
        self.assertEqual(deleted, [])

    def test_start_monitor_reuses_swept_name(self):
        ifindexes = {'wlan0': 3, 'wlan0mon': 42}
        deleted = []

        def fake_delete(name):
            deleted.append(name)
            ifindexes.pop(name, None)
            return True

        modes = {'wlan0': 'managed', 'wlan0mon': 'monitor'}

        with patch('wifite.tools.nexmon.probe', return_value=make_caps()), \
                patch('wifite.tools.nexmon._interface_mode',
                      side_effect=lambda n: modes.get(n)), \
                patch('wifite.tools.nexmon._read_phy', return_value='phy0'), \
                patch('wifite.tools.nexmon._assert_safe_to_take_over'), \
                patch('wifite.tools.nexmon._is_up', return_value=False), \
                patch('wifite.tools.nexmon._is_associated', return_value=False), \
                patch('wifite.tools.nexmon._power_save_state', return_value=False), \
                patch('wifite.tools.nexmon._create_monitor',
                      side_effect=lambda station, phy, monitor:
                      ifindexes.__setitem__(monitor, 43)), \
                patch('wifite.tools.nexmon._ifindex',
                      side_effect=lambda n: ifindexes.get(n)), \
                patch('wifite.tools.nexmon._run_ok', return_value=True), \
                patch('wifite.tools.nexmon._radiotap_monitor_mode', return_value=2), \
                patch('wifite.tools.nexmon._delete_interface', side_effect=fake_delete):
            monitor = nexmon.start_monitor('wlan0')

            self.assertEqual(monitor, 'wlan0mon')
            self.assertEqual(deleted, ['wlan0mon'])
            self.assertEqual(ifindexes.get('wlan0mon'), 43)
            self.assertTrue(Nexmon.has_session('wlan0mon'))
            self.assertTrue(Nexmon.stop('wlan0'))
            self.assertFalse(Nexmon.has_session('wlan0'))
            self.assertFalse(Nexmon.has_session('wlan0mon'))


class TestConfigMonitorModeSetup(unittest.TestCase):
    def setUp(self):
        from wifite.config import Configuration
        self._saved = Configuration.interface

    def tearDown(self):
        from wifite.config import Configuration
        Configuration.interface = self._saved

    def test_interface_flag_still_enables_monitor_mode(self):
        from wifite.config import Configuration
        Configuration.interface = 'wlan0'
        with patch('wifite.tools.airmon.Airmon.start',
                   return_value='wlan0mon') as start, \
                patch('wifite.tools.airmon.Airmon.get_iface_info',
                      return_value=None), \
                patch('wifite.tools.iw.Iw.is_monitor', return_value=False):
            Configuration.get_monitor_mode_interface()
        start.assert_called_once_with('wlan0')
        self.assertEqual(Configuration.interface, 'wlan0mon')

    def test_existing_monitor_interface_left_untouched(self):
        from wifite.config import Configuration
        Configuration.interface = 'wlan0mon'
        with patch('wifite.tools.airmon.Airmon.start') as start, \
                patch('wifite.tools.airmon.Airmon.get_iface_info',
                      return_value=SimpleNamespace(driver='mt76x0u')), \
                patch('wifite.tools.iw.Iw.is_monitor', return_value=True):
            Configuration.get_monitor_mode_interface()
        start.assert_not_called()
        self.assertEqual(Configuration.interface, 'wlan0mon')

    def test_brcmfmac_monitor_still_gets_radiotap_verification(self):
        from wifite.config import Configuration
        from wifite.tools.nexmon import NexmonCapabilities
        Configuration.interface = 'wlan0'
        caps = NexmonCapabilities(
            interface='wlan0', driver='brcmfmac', mask=7, firmware='7.45.265')
        with patch('wifite.tools.airmon.Airmon.start',
                   return_value='wlan0') as start, \
                patch('wifite.tools.airmon.Airmon.get_iface_info',
                      return_value=SimpleNamespace(driver='brcmfmac')), \
                patch('wifite.tools.nexmon.Nexmon.probe', return_value=caps), \
                patch('wifite.tools.iw.Iw.is_monitor', return_value=True):
            Configuration.get_monitor_mode_interface()
        start.assert_called_once_with('wlan0')

    def test_auto_selection_flow_unchanged(self):
        from wifite.config import Configuration
        Configuration.interface = None
        with patch('wifite.tools.airmon.Airmon.ask', return_value='wlan0mon') as ask, \
                patch('wifite.tools.airmon.Airmon.start') as start:
            Configuration.get_monitor_mode_interface()
        ask.assert_called_once()
        start.assert_not_called()
        self.assertEqual(Configuration.interface, 'wlan0mon')


class TestRadiotapMonitorMode(NexmonTestBase):
    def test_radiotap_monitor_mode_parses_monitor_label(self):
        for text, expected in (
            ('monitor: 2\n', 2),
            ('monitor: 0\n', 0),
            ('monitor: -1\n', -1),
            ('2\n', 2),
            ('0\n', 0),
        ):
            result = SimpleNamespace(returncode=0, stdout=text, stderr='')
            with patch('wifite.tools.nexmon._run', return_value=result):
                self.assertEqual(nexmon._radiotap_monitor_mode('wlan0mon'), expected)

    def test_radiotap_monitor_mode_handles_failure(self):
        result = SimpleNamespace(returncode=1, stdout='', stderr='error')
        with patch('wifite.tools.nexmon._run', return_value=result):
            self.assertIsNone(nexmon._radiotap_monitor_mode('wlan0mon'))

        result = SimpleNamespace(returncode=0, stdout='invalid string', stderr='')
        with patch('wifite.tools.nexmon._run', return_value=result):
            self.assertIsNone(nexmon._radiotap_monitor_mode('wlan0mon'))


if __name__ == '__main__':
    unittest.main()
