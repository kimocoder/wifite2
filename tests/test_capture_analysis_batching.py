import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from wifite.model.target import WPSState
from wifite.tools.tshark import Tshark


class TestCaptureAnalysisBatching(unittest.TestCase):
    def test_wps_status_map(self):
        process = MagicMock()
        process.get_output.return_value = ((
            'AA:BB:CC:DD:EE:FF,\n'
            '11:22:33:44:55:66,1\n'
            'not-a-mac,0\n'
            'AA:BB:CC:DD:EE:FF,0x01\n'
        ), '')
        process.poll.return_value = 0

        with patch.object(Tshark, 'exists', return_value=True), \
                patch('wifite.tools.tshark.Process', return_value=process):
            result = Tshark.get_wps_status_map('capture.cap')

        self.assertEqual(result, {
            'AA:BB:CC:DD:EE:FF': WPSState.UNLOCKED,
            '11:22:33:44:55:66': WPSState.LOCKED,
        })

    def test_wps_update_marks_missing_targets_none(self):
        process = MagicMock()
        process.get_output.return_value = ('AA:BB:CC:DD:EE:FF,0\n', '')
        process.poll.return_value = 0
        present = SimpleNamespace(bssid='AA:BB:CC:DD:EE:FF', wps=WPSState.UNKNOWN)
        missing = SimpleNamespace(bssid='11:22:33:44:55:66', wps=WPSState.UNKNOWN)

        with patch.object(Tshark, 'exists', return_value=True), \
                patch('wifite.tools.tshark.Process', return_value=process):
            Tshark.check_for_wps_and_update_targets('capture.cap', [present, missing])

        self.assertEqual(present.wps, WPSState.UNLOCKED)
        self.assertEqual(missing.wps, WPSState.NONE)

    def test_wpa3_batch_parses_all_targets_with_one_call(self):
        from wifite.util.wpa3 import WPA3Detector

        output = (
            'AA:BB:CC:DD:EE:FF\t1\t0\t\n'
            'AA:BB:CC:DD:EE:FF\t\t\t24\n'
            'AA:BB:CC:DD:EE:FF\t\t\t19\n'
            'AA:BB:CC:DD:EE:FF\t\t\t24\n'
            '11:22:33:44:55:66\t0\t1\t\n'
            'not-a-mac\t1\t0\t\n'
            'malformed-row\n'
        )
        process = MagicMock()
        process.get_output.return_value = (output, '')
        process.poll.return_value = 0

        with patch('wifite.tools.tshark.Tshark.exists', return_value=True), \
                patch('wifite.util.process.Process', return_value=process) as process_class:
            result = WPA3Detector.parse_capture_batch('capture.cap')

        self.assertEqual(process_class.call_count, 1)
        self.assertEqual(result, {
            'AA:BB:CC:DD:EE:FF': {
                'pmf_status': WPA3Detector.PMF_OPTIONAL,
                'sae_groups': [19, 24],
            },
            '11:22:33:44:55:66': {
                'pmf_status': WPA3Detector.PMF_REQUIRED,
                'sae_groups': [],
            },
        })

    @staticmethod
    def make_scanner():
        from wifite.tools.airodump import Airodump

        scanner = Airodump.__new__(Airodump)
        scanner.skip_wps = False
        scanner._capture_analysis_signature = None
        scanner._wps_capture_cache = {}
        scanner._wpa3_capture_cache = {}
        return scanner

    @staticmethod
    def make_target(bssid):
        from wifite.model.target import Target

        return Target([
            bssid, '2024-01-01 00:00:00', '2024-01-01 00:00:01',
            '6', '54', 'WPA2 WPA3', 'CCMP', 'PSK SAE', '-50',
            '10', '0', '0.0.0.0', '8', 'TestNet', '',
        ])

    def test_unchanged_capture_uses_zero_tshark_calls(self):
        import tempfile

        scanner = self.make_scanner()
        targets = [self.make_target('AA:BB:CC:DD:EE:FF'), self.make_target('11:22:33:44:55:66')]
        wps_map = {target.bssid: WPSState.UNLOCKED for target in targets}
        wpa3_map = {target.bssid: {'pmf_status': 'optional', 'sae_groups': [19]} for target in targets}

        with tempfile.NamedTemporaryFile() as capture, \
                patch('wifite.tools.airodump.Tshark.get_wps_status_map', return_value=wps_map) as wps_call, \
                patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch', return_value=wpa3_map) as wpa3_call:
            scanner._analyze_capture(capture.name, targets)
            scanner._analyze_capture(capture.name, targets)

        self.assertEqual(wps_call.call_count, 1)
        self.assertEqual(wpa3_call.call_count, 1)

    def test_new_target_uses_cached_analysis(self):
        import tempfile
        from wifite.util.wpa3 import WPA3Detector

        scanner = self.make_scanner()
        first = self.make_target('AA:BB:CC:DD:EE:FF')
        new_bssid = '11:22:33:44:55:66'
        wps_map = {new_bssid: WPSState.LOCKED}
        wpa3_map = {new_bssid: {'pmf_status': WPA3Detector.PMF_REQUIRED, 'sae_groups': [22]}}

        with tempfile.NamedTemporaryFile() as capture, \
                patch('wifite.tools.airodump.Tshark.get_wps_status_map', return_value=wps_map) as wps_call, \
                patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch', return_value=wpa3_map) as wpa3_call:
            scanner._analyze_capture(capture.name, [first])
            new_target = self.make_target(new_bssid)
            scanner._analyze_capture(capture.name, [new_target])

        self.assertEqual(wps_call.call_count, 1)
        self.assertEqual(wpa3_call.call_count, 1)
        self.assertEqual(new_target.wps, WPSState.LOCKED)
        self.assertEqual(new_target.wpa3_info.pmf_status, WPA3Detector.PMF_REQUIRED)
        self.assertEqual(new_target.wpa3_info.sae_groups, [22])
        self.assertTrue(new_target.wpa3_info.dragonblood_vulnerable)

    def test_changed_capture_invalidates_cache(self):
        import tempfile

        scanner = self.make_scanner()
        target = self.make_target('AA:BB:CC:DD:EE:FF')
        states = [
            {target.bssid: WPSState.UNLOCKED},
            {target.bssid: WPSState.LOCKED},
        ]

        with tempfile.NamedTemporaryFile() as capture, \
                patch('wifite.tools.airodump.Tshark.get_wps_status_map', side_effect=states) as wps_call, \
                patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch', return_value={}) as wpa3_call:
            scanner._analyze_capture(capture.name, [target])
            capture.write(b'new frame')
            capture.flush()
            scanner._analyze_capture(capture.name, [target])

        self.assertEqual(wps_call.call_count, 2)
        self.assertEqual(wpa3_call.call_count, 2)
        self.assertEqual(target.wps, WPSState.LOCKED)

    def test_replaced_capture_invalidates_cache(self):
        import os
        import tempfile

        scanner = self.make_scanner()
        target = self.make_target('AA:BB:CC:DD:EE:FF')

        with tempfile.TemporaryDirectory() as temp_dir, \
                patch('wifite.tools.airodump.Tshark.get_wps_status_map', return_value={}) as wps_call, \
                patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch', return_value={}) as wpa3_call:
            capture = os.path.join(temp_dir, 'capture.cap')
            replacement = os.path.join(temp_dir, 'replacement.cap')
            for path in (capture, replacement):
                with open(path, 'wb') as output:
                    output.write(b'x')

            scanner._analyze_capture(capture, [target])
            os.replace(replacement, capture)
            scanner._analyze_capture(capture, [target])

        self.assertEqual(wps_call.call_count, 2)
        self.assertEqual(wpa3_call.call_count, 2)

    def test_missing_tshark_preserves_fallback(self):
        import tempfile

        scanner = self.make_scanner()
        target = self.make_target('AA:BB:CC:DD:EE:FF')

        def use_wash(_, targets):
            targets[0].wps = WPSState.UNLOCKED

        with tempfile.NamedTemporaryFile() as capture, \
                patch('wifite.tools.airodump.Tshark.exists', return_value=False), \
                patch('wifite.tools.airodump.Tshark.get_wps_status_map', side_effect=ValueError), \
                patch('wifite.tools.airodump.Tshark.check_for_wps_and_update_targets', side_effect=ValueError), \
                patch('wifite.tools.airodump.Wash.check_for_wps_and_update_targets', side_effect=use_wash) as wash_call, \
                patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch', return_value={}):
            scanner._analyze_capture(capture.name, [target])

        self.assertEqual(wash_call.call_count, 1)
        self.assertEqual(target.wps, WPSState.UNLOCKED)
        self.assertIsNone(scanner._capture_analysis_signature)

    def test_wpa3_batch_rejects_failed_tshark(self):
        from wifite.util.wpa3 import WPA3Detector

        process = MagicMock()
        process.get_output.return_value = ('', 'unknown field')
        process.poll.return_value = 2

        with patch('wifite.tools.tshark.Tshark.exists', return_value=True), \
                patch('wifite.util.process.Process', return_value=process):
            with self.assertRaisesRegex(ValueError, 'tshark'):
                WPA3Detector.parse_capture_batch('capture.cap')

    def test_wps_rejects_failed_tshark(self):
        process = MagicMock()
        process.get_output.return_value = ('', 'capture error')
        process.poll.return_value = 2

        with patch.object(Tshark, 'exists', return_value=True), \
                patch('wifite.tools.tshark.Process', return_value=process):
            with self.assertRaises(ValueError):
                Tshark.get_wps_status_map('capture.cap')

    def test_failed_analysis_retries_unchanged_capture(self):
        import tempfile

        scanner = self.make_scanner()
        target = self.make_target('AA:BB:CC:DD:EE:FF')

        with tempfile.NamedTemporaryFile() as capture, \
                patch('wifite.tools.airodump.Tshark.exists', return_value=True), \
                patch('wifite.tools.airodump.Tshark.get_wps_status_map', side_effect=ValueError) as wps_call, \
                patch('wifite.tools.airodump.Tshark.check_for_wps_and_update_targets', side_effect=AssertionError), \
                patch('wifite.tools.airodump.Wash.check_for_wps_and_update_targets') as wash_call, \
                patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch', return_value={}):
            scanner._analyze_capture(capture.name, [target])
            scanner._analyze_capture(capture.name, [target])

        self.assertEqual(wps_call.call_count, 2)
        self.assertEqual(wash_call.call_count, 2)
        self.assertIsNone(scanner._capture_analysis_signature)

    def test_replaced_capture_clears_stale_wpa3_evidence(self):
        import os
        import tempfile
        from wifite.util.wpa3 import WPA3Detector

        scanner = self.make_scanner()
        old_target = self.make_target('AA:BB:CC:DD:EE:FF')
        parsed = {
            old_target.bssid: {
                'pmf_status': WPA3Detector.PMF_REQUIRED,
                'sae_groups': [22],
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir, \
                patch('wifite.tools.airodump.Tshark.exists', return_value=True), \
                patch('wifite.tools.airodump.Tshark.get_wps_status_map', return_value={}), \
                patch('wifite.tools.airodump.WPA3Detector.parse_capture_batch', side_effect=[parsed, {}]):
            capture = os.path.join(temp_dir, 'capture.cap')
            replacement = os.path.join(temp_dir, 'replacement.cap')
            for path in (capture, replacement):
                with open(path, 'wb') as output:
                    output.write(b'x')

            scanner._analyze_capture(capture, [old_target])
            new_target = self.make_target(old_target.bssid)
            old_target.transfer_info(new_target)
            os.replace(replacement, capture)
            scanner._analyze_capture(capture, [new_target])

        self.assertEqual(new_target.wpa3_info.pmf_status, WPA3Detector.PMF_OPTIONAL)
        self.assertEqual(new_target.wpa3_info.sae_groups, [19])
        self.assertFalse(new_target.wpa3_info.dragonblood_vulnerable)

    def test_real_tshark_batch_fields_are_valid(self):
        import shutil
        from wifite.util.wpa3 import WPA3Detector

        if not shutil.which('tshark'):
            self.skipTest('tshark is not installed')

        result = WPA3Detector.parse_capture_batch('tests/files/contains_wps_network.cap')

        self.assertEqual(result, {
            'A4:2B:8C:16:6B:3A': {
                'pmf_status': WPA3Detector.PMF_DISABLED,
                'sae_groups': [],
            }
        })


if __name__ == '__main__':
    unittest.main()
