#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Session state for 'captured but not cracked' targets."""

import sys
import tempfile
import unittest

import pytest

sys.path.insert(0, '..')

from wifite.util.session import SessionManager, SessionState, TargetState


def mark_target_captured(session, bssid, reason):
    SessionManager(session_dir=tempfile.mkdtemp()).mark_target_captured(
        session, bssid, reason)

pytestmark = pytest.mark.timeout(30)

BSSID = '5C:E2:8C:23:DC:B0'


def make_session():
    target = TargetState(
        bssid=BSSID,
        essid='CYBERSPACE',
        channel=6,
        encryption='WPA2',
        power=50,
        wps=False,
    )
    return SessionState(
        session_id='test_captured',
        created_at=1234567890.0,
        updated_at=1234567890.0,
        config={'target_bssid': BSSID},
        targets=[target],
    )


class TestCapturedState(unittest.TestCase):
    def test_mark_target_captured(self):
        session = make_session()
        mark_target_captured(session, BSSID, 'captured but not cracked')

        assert session.captured_targets[BSSID] == 'captured but not cracked'
        assert session.targets[0].status == 'captured'
        assert session.targets[0].attempts == 1

    def test_serialization_roundtrip(self):
        session = make_session()
        mark_target_captured(session, BSSID, 'crack tool unavailable; capture kept')

        restored = SessionState.from_dict(session.to_dict())

        assert restored.captured_targets == session.captured_targets
        assert restored.targets[0].status == 'captured'

    def test_progress_summary_counts_captured(self):
        session = make_session()
        mark_target_captured(session, BSSID, 'captured but not cracked')

        progress = session.get_progress_summary()

        assert progress['total'] == 1
        assert progress['captured'] == 1
        assert progress['completed'] == 0
        assert progress['failed'] == 0
        assert progress['remaining'] == 0

    def test_captured_targets_skipped_unless_requested(self):
        manager = SessionManager(session_dir=tempfile.mkdtemp())
        session = make_session()
        mark_target_captured(session, BSSID, 'captured but not cracked')

        assert manager.get_remaining_targets(session) == []
        assert len(manager.get_remaining_targets(
            session, include_captured=True)) == 1

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SessionManager(session_dir=tmpdir)
            session = make_session()
            mark_target_captured(session, BSSID, 'captured but not cracked')

            manager.save_session(session)
            loaded = manager.load_session(session.session_id)

            assert loaded.captured_targets == session.captured_targets
            assert loaded.targets[0].status == 'captured'

    def test_validation_accepts_captured_status(self):
        session = make_session()
        mark_target_captured(session, BSSID, 'captured but not cracked')

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SessionManager(session_dir=tmpdir)
            manager._validate_session_data(
                session.to_dict(), session.session_id)


if __name__ == '__main__':
    unittest.main()