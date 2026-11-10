"""The reason must describe THIS hcxdumptool session, not an older one."""

from unittest.mock import MagicMock, patch

from wifite.tools.hcxdumptool import HcxDumpTool, HcxDumpToolPassive

ERROR = 'failed to get interface index: No such device'


def _make_tool():
    with patch('wifite.tools.hcxdumptool.Configuration.initialize'):
        return HcxDumpTool(interface='wlan0', output_file='/tmp/x.pcapng')


def _make_passive():
    with patch('wifite.tools.hcxdumptool.Configuration.initialize'):
        return HcxDumpToolPassive(interface='wlan0', output_file='/tmp/x.pcapng')


def test_previous_session_in_the_same_log_is_ignored(tmp_path):
    """The log is per scope and appended across spawns; only our tail counts."""
    first = ('2 ERROR(s) during runtime:\n'
             ' -mostly caused by a broken driver\n'
             'exit on sigterm\n')
    log = tmp_path / 'shared.log'
    log.write_text(first + 'starting in headless mode (--rds=0 display off)...\n'
                   + ERROR + '\n')
    tool = _make_tool()
    tool.log_path = str(log)
    tool._log_offset = len(first)
    assert tool.get_failure_reason() == ERROR


def test_partial_first_line_from_the_read_window_is_dropped(tmp_path):
    """A 4 KiB window opens mid-line; a fragment is not a reason."""
    log = tmp_path / 'wide.log'
    log.write_text('x' * 10000 + '\n  1|00:03:15|ep|CL|AP|ESSID\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == ''


def test_passive_error_on_stdout_survives_a_stderr_warning():
    """The passive fallback must not hide stdout behind a startup warning."""
    tool = _make_passive()
    tool.proc = MagicMock()
    tool.proc.get_output.return_value = (
        ERROR, 'warning possible interfere: NetworkManager is running')
    assert tool.get_failure_reason() == ERROR


def test_missing_log_file_is_not_an_error(tmp_path):
    tool = _make_tool()
    tool.log_path = str(tmp_path / 'never-written.log')
    assert tool.get_failure_reason() == ''