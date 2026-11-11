"""Cleanup must survive the driver refusing a mode/channel change."""

from unittest.mock import MagicMock, patch

from wifite.util.interface_manager import InterfaceManager

BUSY = MagicMock(returncode=240,
                 stderr='command failed: Device or resource busy (-16)', stdout='')


def test_busy_is_tolerated_when_asked():
    with patch('wifite.util.interface_manager.Process.run_simple', return_value=BUSY), \
         patch('wifite.util.interface_manager.log_error') as log_error, \
         patch('wifite.util.interface_manager.log_debug'):
        ok = InterfaceManager._run_checked(
            ['iw', 'dev', 'wlan1', 'set', 'channel', '3'], tolerate_busy=True)

    assert ok is True
    log_error.assert_not_called()


def test_busy_is_an_error_by_default():
    with patch('wifite.util.interface_manager.Process.run_simple', return_value=BUSY), \
         patch('wifite.util.interface_manager.log_error') as log_error, \
         patch('wifite.util.interface_manager.log_debug'):
        ok = InterfaceManager._run_checked(
            ['ip', 'link', 'set', 'wlan1', 'down'])

    assert ok is False
    log_error.assert_called_once()
