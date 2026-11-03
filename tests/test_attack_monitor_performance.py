import unittest
from unittest.mock import MagicMock, patch

from wifite.attack.attack_monitor import AttackMonitor


def attack_event(bssid, source_mac, timestamp):
    return {
        'bssid': bssid,
        'source_mac': source_mac,
        'dest_mac': 'FF:FF:FF:FF:FF:FF',
        'type': 'deauth',
        'timestamp': timestamp,
        'essid': 'TestNetwork',
        'channel': 6,
    }


class TestAttackMonitorPerformance(unittest.TestCase):
    def test_expired_networks_and_attackers_are_pruned(self):
        monitor = AttackMonitor()
        old = attack_event('AA:BB:CC:DD:EE:FF', '00:11:22:33:44:55', 1000)
        new = attack_event('11:22:33:44:55:66', '66:55:44:33:22:11', 1601)

        with patch('wifite.attack.attack_monitor.time.time', return_value=1000):
            monitor.track_attack(old)
        monitor.networks_under_attack[old['bssid']]['last_seen'] = 1000
        monitor.attacker_macs[old['source_mac']]['last_seen'] = 1000

        with patch('wifite.attack.attack_monitor.time.time', return_value=1601):
            monitor.track_attack(new)

        self.assertNotIn(old['bssid'], monitor.networks_under_attack)
        self.assertNotIn(old['source_mac'], monitor.attacker_macs)
        self.assertIn(new['bssid'], monitor.networks_under_attack)
        self.assertIn(new['source_mac'], monitor.attacker_macs)

    def test_tracking_state_has_hard_lru_caps(self):
        monitor = AttackMonitor()
        monitor.MAX_TRACKED_NETWORKS = 2
        monitor.MAX_TRACKED_ATTACKERS = 2
        events = [
            attack_event('AA:BB:CC:DD:EE:01', '00:00:00:00:00:01', 1000),
            attack_event('AA:BB:CC:DD:EE:02', '00:00:00:00:00:02', 1001),
            attack_event('AA:BB:CC:DD:EE:03', '00:00:00:00:00:03', 1002),
        ]

        with patch('wifite.attack.attack_monitor.time.time', side_effect=[1000, 1001, 1002]):
            for event in events:
                monitor.track_attack(event)

        self.assertEqual(len(monitor.networks_under_attack), 2)
        self.assertEqual(len(monitor.attacker_macs), 2)
        self.assertNotIn(events[0]['bssid'], monitor.networks_under_attack)
        self.assertNotIn(events[0]['source_mac'], monitor.attacker_macs)

    def test_tui_statistics_refresh_is_throttled(self):
        monitor = AttackMonitor()
        monitor.tui_view = MagicMock()

        with patch('wifite.attack.attack_monitor.time.time', side_effect=[1.0, 1.1, 1.2, 1.5]):
            for _ in range(4):
                monitor.update_statistics()

        self.assertEqual(monitor.tui_view.update_attack_statistics.call_count, 2)

    def test_classic_statistics_refresh_is_throttled(self):
        monitor = AttackMonitor()

        with patch('wifite.attack.attack_monitor.time.time', side_effect=[1.0, 1.1, 1.2, 1.5]), \
                patch('wifite.attack.attack_monitor.Color.clear_entire_line') as clear_line, \
                patch('wifite.attack.attack_monitor.Color.p'):
            for _ in range(4):
                monitor.display_statistics()

        self.assertEqual(clear_line.call_count, 2)

    def test_tui_top_lists_do_not_fully_sort_tracking_dictionaries(self):
        monitor = AttackMonitor()
        monitor.tui_view = MagicMock()

        with patch('wifite.attack.attack_monitor.time.time', return_value=1.0), \
                patch('wifite.attack.attack_monitor.sorted', side_effect=AssertionError, create=True):
            monitor.update_statistics()

        self.assertEqual(monitor.tui_view.update_attack_statistics.call_count, 1)


if __name__ == '__main__':
    unittest.main()
