"""Passive PMKID must report networks seen, not hashes extracted."""

from unittest.mock import patch

from wifite.attack.pmkid_passive import AttackPassivePMKID, count_networks


def _capture(tmp_path, payload=b'\x00' * 16):
    cap = tmp_path / 'capture.pcapng'
    cap.write_bytes(payload)
    return str(cap)


def test_counts_unique_bssids(tmp_path):
    cap = _capture(tmp_path)
    with patch('wifite.attack.pmkid_passive.Process') as proc, \
         patch('wifite.tools.tshark.Tshark.exists', return_value=True):
        proc.call.return_value = (
            'aa:bb:cc:00:00:01\nAA:BB:CC:00:00:01\ndd:ee:ff:00:00:02\n', '')
        assert count_networks(cap) == 2


def test_returns_none_without_tshark(tmp_path):
    cap = _capture(tmp_path)
    with patch('wifite.tools.tshark.Tshark.exists', return_value=False):
        assert count_networks(cap) is None


def test_returns_none_for_missing_file(tmp_path):
    assert count_networks(str(tmp_path / 'absent.pcapng')) is None


def test_statistics_use_the_network_count(tmp_path):
    cap = _capture(tmp_path)
    attack = object.__new__(AttackPassivePMKID)
    attack.pcapng_file = cap
    attack.captured_pmkids = {}
    attack.statistics = {
        'networks_detected': 0, 'pmkids_captured': 0, 'last_extraction': None}
    attack.tui_view = None
    attack.save_pmkid_hash = lambda bssid, essid, pmkid_hash: None

    pmkids = [{'bssid': 'AA:BB:CC:00:00:01', 'essid': 'one', 'hash': 'WPA*01*'},
              {'bssid': 'DD:EE:FF:00:00:02', 'essid': 'two', 'hash': 'WPA*01*'}]

    with patch.object(AttackPassivePMKID, 'save_pmkid_hash', lambda *a: None), \
         patch('wifite.attack.pmkid_passive.HcxPcapngTool.extract_all_pmkids',
               return_value=pmkids), \
         patch('wifite.attack.pmkid_passive.count_networks', return_value=7):
        attack.extract_and_save_pmkids()

    assert attack.statistics['networks_detected'] == 7