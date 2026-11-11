"""`--version` must exist and print the packaged version."""

import sys

import pytest

from wifite.args import Arguments
from wifite.config import Configuration
from wifite.config.defaults import initialize_defaults


def test_version_flag_prints_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['wifite', '--version'])
    initialize_defaults(Configuration)

    with pytest.raises(SystemExit) as caught:
        Arguments(Configuration)

    assert caught.value.code == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith('wifite2 ')
    assert Configuration.version in out