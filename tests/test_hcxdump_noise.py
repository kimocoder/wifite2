"""A log of startup warnings must not be reported as a failure reason."""

from unittest.mock import patch

from wifite.tools.hcxdumptool import HcxDumpTool


def _make_tool():
    with patch('wifite.tools.hcxdumptool.Configuration.initialize'):
        return HcxDumpTool(interface='wlan0', output_file='/tmp/x.pcapng')


def test_startup_warnings_are_not_a_reason(tmp_path):
    """hcxdumptool prints these on every start; they explain nothing."""
    log = tmp_path / 'warn.log'
    log.write_text('This is a highly experimental penetration testing tool!\n'
                   'It is made to detect vulnerabilities in your NETWORK mercilessly!\n'
                   'Warning: BPF is unset!\n'
                   'Make sure hcxdumptool is running in a 100% controlled environment!\n'
                   'warning possible interfere: NetworkManager is running\n'
                   'starting in headless mode (--rds=0 display off)...\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == ''


def test_an_error_among_warnings_is_still_reported(tmp_path):
    log = tmp_path / 'mixed.log'
    log.write_text('Warning: BPF is unset!\n'
                   'warning possible interfere: NetworkManager is running\n'
                   'failed to get interface index: No such device\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == \
        'failed to get interface index: No such device'


def test_packet_statistics_are_not_a_reason(tmp_path):
    """Counters say how much was captured, never why it stopped."""
    log = tmp_path / 'stats.log'
    log.write_text('1234 Packet(s) captured by kernel\n'
                   '0 Packet(s) dropped by kernel\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == ''