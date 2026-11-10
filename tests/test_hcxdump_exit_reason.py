"""hcxdumptool's own stop lines must be translated, never mask real errors."""

from unittest.mock import MagicMock, patch

from wifite.tools.hcxdumptool import HcxDumpTool, _exit_reason

WATCHDOG = 'no packets received (watchdog timeout)'
TOT = 'capture timer expired'
ERRORS = '2 runtime error(s); usually a broken driver or a shared interface'


def _make_tool():
    with patch('wifite.tools.hcxdumptool.Configuration.initialize'):
        return HcxDumpTool(interface='wlan0', output_file='/tmp/x.pcapng')


# --- the translator -------------------------------------------------------

def test_watchdog_exit_is_explained():
    assert _exit_reason('0 Packet(s) captured by kernel\nexit on watchdog\n') == WATCHDOG


def test_tot_exit_is_explained():
    assert _exit_reason('18 Packet(s) captured by kernel\nexit on TOT\n') == TOT


def test_error_count_beats_trailing_sigterm():
    """Our own SIGTERM must not hide the errors that preceded it."""
    text = ('2 ERROR(s) during runtime:\n'
            ' -mostly caused by a broken driver\n'
            ' -running hcxdumptool on a shared interface)\n'
            ' -a misconfigured system\n'
            'exit on sigterm\n')
    assert _exit_reason(text) == ERRORS


def test_clean_sigterm_stop_is_not_a_failure():
    assert _exit_reason('3213 Packet(s) captured by kernel\nexit on sigterm\n') == ''


def test_successful_exitoneapol_stop_is_not_a_failure():
    assert _exit_reason('exit on eapol\n') == ''


def test_unknown_error_text_is_left_alone():
    assert _exit_reason('failed to get interface index: No such device\n') == ''


def test_ansi_escapes_and_progress_rows_do_not_defeat_matching():
    text = ('\x1b[?25l\n'
            '  1|00:03:06|ep++  |42d63c0f2ffd|000101032BB9|YHLX_XM\r\n'
            '\x1b[?25h0 Packet(s) captured by kernel\n'
            'exit on watchdog\n')
    assert _exit_reason(text) == WATCHDOG


# --- the targeted wrapper's accessor --------------------------------------

def test_reason_from_piped_stdout():
    tool = _make_tool()
    tool.proc = MagicMock()
    tool.proc.get_output.return_value = (
        '0 Packet(s) captured by kernel\nexit on watchdog\n', '')
    assert tool.get_failure_reason() == WATCHDOG


def test_reason_from_piped_stderr():
    """hcxdumptool need not use the same stream for its stop line."""
    tool = _make_tool()
    tool.proc = MagicMock()
    tool.proc.get_output.return_value = ('', 'exit on watchdog\n')
    assert tool.get_failure_reason() == WATCHDOG


def test_reason_from_supervisor_log(tmp_path):
    """Supervised runs redirect stdio to a log file, so get_output() is empty."""
    log = tmp_path / 'hcxdumptool_1.log'
    log.write_text('starting in headless mode (--rds=0 display off)...\n'
                   '0 Packet(s) captured by kernel\n'
                   'exit on watchdog\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == WATCHDOG


def test_reason_empty_without_process_or_log():
    tool = _make_tool()
    assert tool.proc is None and tool.log_path is None
    assert tool.get_failure_reason() == ''


def test_reason_reads_tail_of_large_log(tmp_path):
    log = tmp_path / 'big.log'
    log.write_text('filler line\n' * 1200 + 'exit on watchdog\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == WATCHDOG


def test_error_text_passes_through_from_log(tmp_path):
    log = tmp_path / 'err.log'
    log.write_text('\x1b[?25h\n'
                   'failed to get interface index: No such device\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == \
        'failed to get interface index: No such device'


def test_display_rows_alone_yield_no_reason(tmp_path):
    log = tmp_path / 'rows.log'
    log.write_text('  1|00:03:06|ep++  |42d63c0f2ffd|000101032BB9|YHLX_XM\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == ''


def test_clean_sigterm_log_yields_no_reason(tmp_path):
    log = tmp_path / 'clean.log'
    log.write_text('3213 Packet(s) captured by kernel\n'
                   '0 Packet(s) dropped by kernel\n'
                   'exit on sigterm\n')
    tool = _make_tool()
    tool.log_path = str(log)
    assert tool.get_failure_reason() == ''