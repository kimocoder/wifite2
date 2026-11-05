import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from wifite.attack.pmkid import AttackPMKID


class TestHcxDumpToolDeath(unittest.TestCase):
    """hcxdumptool dies instantly on brcmfmac ('failed to arm interface');
    the PMKID loop must not spin for the full timeout without a capturer."""

    def _attack(self):
        attack = AttackPMKID.__new__(AttackPMKID)
        attack.target = SimpleNamespace(
            essid='CYBERSPACE', bssid='5C:E2:8C:23:DC:B0', channel=1)
        attack.view = None
        attack.pcapng_file = '/tmp/nonexistent-pmkid-test.pcapng'
        attack.success = False
        return attack

    def _run(self, native_available):
        attack = self._attack()
        dumptool = MagicMock()
        dumptool.is_running.return_value = False  # process already dead
        dumptool_cls = MagicMock()
        dumptool_cls.return_value.__enter__.return_value = dumptool
        pcaptool = MagicMock()
        pcaptool.return_value.get_pmkid_hash.return_value = None

        with patch('wifite.attack.pmkid.HcxDumpTool', dumptool_cls), \
                patch('wifite.attack.pmkid.HcxPcapngTool', pcaptool), \
                patch('wifite.attack.pmkid.NATIVE_PMKID_AVAILABLE', native_available), \
                patch('wifite.attack.pmkid.Configuration') as config, \
                patch('wifite.util.process.Process.check_fd_limit', return_value=False), \
                patch.object(AttackPMKID, 'capture_pmkid_native',
                             return_value='/tmp/native.22000') as native, \
                patch('wifite.util.color.Color.pattack'), \
                patch('wifite.util.color.Color.pl'):
            config.pmkid_timeout = 300
            config.verbose = 0
            return attack, attack.capture_pmkid(), native

    def test_dead_hcxdumptool_falls_back_to_native(self):
        attack, result, native = self._run(native_available=True)
        native.assert_called_once_with()
        self.assertEqual(result, '/tmp/native.22000')

    def test_dead_hcxdumptool_fails_fast_without_native(self):
        import time
        start = time.monotonic()
        attack, result, native = self._run(native_available=False)
        elapsed = time.monotonic() - start
        self.assertIsNone(result)
        native.assert_not_called()
        self.assertLess(elapsed, 30, 'spun instead of aborting after tool death')


class TestExitMonitorNote(unittest.TestCase):
    def _exit(self, is_monitor):
        from wifite.config import Configuration
        from wifite.tools.airmon import Airmon
        saved_interface = Configuration.interface
        saved_daemon = Configuration.daemon
        Configuration.interface = 'wlan0mon'
        Configuration.daemon = False
        Airmon.base_interface = 'wlan0'
        try:
            with patch('wifite.tools.nexmon.Nexmon.cleanup_all', return_value=[]), \
                    patch('wifite.tools.iw.Iw.is_monitor', return_value=is_monitor), \
                    patch('wifite.tools.macchanger.Macchanger.reset_if_changed'), \
                    patch('wifite.util.color.Color.pl') as color_pl:
                Configuration.temp_dir = None
                Configuration.interface_manager = None
                try:
                    Configuration.exit_gracefully()
                except SystemExit:
                    pass
            messages = [c[0][0] for c in color_pl.call_args_list if c[0]]
            return any('Leaving interface in Monitor Mode' in m for m in messages)
        finally:
            Configuration.interface = saved_interface
            Configuration.daemon = saved_daemon
            Airmon.base_interface = None

    def test_no_note_when_monitor_already_torn_down(self):
        self.assertFalse(self._exit(is_monitor=False))

    def test_note_when_monitor_still_active(self):
        self.assertTrue(self._exit(is_monitor=True))


class TestScapyInterfaceCacheRefresh(unittest.TestCase):
    def test_capture_reloads_scapy_interface_cache(self):
        from wifite.native import pmkid as native_pmkid
        from scapy.all import conf

        with patch.object(conf.ifaces, 'reload') as reload_mock, \
                patch.object(native_pmkid, 'sniff', return_value=[]):
            result = native_pmkid.ScapyPMKID.capture(
                interface='wlan0mon',
                bssid='5C:E2:8C:23:DC:B0',
                timeout=1,
                send_auth=False,
            )
        reload_mock.assert_called_once()
        self.assertIsNone(result)


class TestEvilTwinApConfig(unittest.TestCase):
    def _configure(self, has_session):
        from wifite.attack.eviltwin import EvilTwin
        attack = EvilTwin.__new__(EvilTwin)
        with patch('wifite.tools.nexmon.Nexmon.has_session',
                   return_value=has_session), \
                patch('wifite.tools.nexmon.Nexmon.stop', return_value=True) as stop, \
                patch('wifite.tools.airmon.Airmon.put_interface_down'), \
                patch('wifite.tools.airmon.Airmon.put_interface_up'), \
                patch('wifite.tools.airmon.Airmon.set_interface_mode',
                      return_value=True):
            result = attack._configure_ap_interface('wlan0')
        return result, stop

    def test_ap_config_stops_nexmon_session(self):
        result, stop = self._configure(has_session=True)
        self.assertTrue(result)
        stop.assert_called_once_with('wlan0')

    def test_ap_config_without_session_untouched(self):
        result, stop = self._configure(has_session=False)
        self.assertTrue(result)
        stop.assert_not_called()


if __name__ == '__main__':
    unittest.main()
