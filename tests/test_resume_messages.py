"""A missing --resume-id must not claim the session list is empty."""

import unittest
from unittest.mock import MagicMock, patch

from wifite.config import Configuration
from wifite.wifite import Wifite

SESSIONS = [
    {'session_id': 'session_20261110_235545', 'total_targets': 2,
     'completed': 1, 'captured': 0, 'failed': 0, 'remaining': 1},
    {'session_id': 'session_20261110_235335', 'total_targets': 1,
     'completed': 1, 'captured': 1, 'failed': 0, 'remaining': 0},
]


def _printed(mock_pl):
    return ' '.join(str(call.args[0]) for call in mock_pl.call_args_list)


class TestResumeMessages(unittest.TestCase):

    def run_resume(self, load_side_effect, resume_id='session_missing'):
        manager = MagicMock()
        manager.load_session.side_effect = load_side_effect
        manager.list_sessions.return_value = SESSIONS

        with patch.object(Configuration, 'resume_id', resume_id, create=True), \
             patch.object(Configuration, 'resume_latest', False, create=True), \
             patch('wifite.util.session.SessionManager', return_value=manager), \
             patch('wifite.wifite.Color.pl') as pl, \
             patch('wifite.util.input.input', side_effect=KeyboardInterrupt):
            with self.assertRaises(SystemExit) as caught:
                Wifite.resume_session()

        return caught.exception.code, _printed(pl)

    def test_unknown_id_lists_available_sessions(self):
        code, text = self.run_resume(
            FileNotFoundError('Session file not found: session_missing'))

        self.assertEqual(code, 1)
        self.assertIn('not found', text)
        self.assertIn('session_20261110_235545', text)
        self.assertNotIn('No session files found to resume', text)

    def test_corrupt_file_is_reported_distinctly(self):
        code, text = self.run_resume(ValueError('invalid JSON'))

        self.assertEqual(code, 1)
        self.assertIn('Corrupted', text)


if __name__ == '__main__':
    unittest.main()