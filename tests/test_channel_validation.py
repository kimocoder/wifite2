"""`-c` must reject channels that cannot exist."""

import pytest

from wifite.config import Configuration
from wifite.config.validators import validate
from wifite.util.errors import WifiteError


def _validate_with(channel, monkeypatch):
    monkeypatch.setattr(Configuration, 'target_channel', channel, raising=False)
    monkeypatch.setattr(Configuration, 'target_timeout', 0)
    monkeypatch.setattr(Configuration, 'use_pmkid_only', False)
    monkeypatch.setattr(Configuration, 'wps_only', False)
    monkeypatch.setattr(Configuration, 'dont_use_pmkid', False)
    monkeypatch.setattr(Configuration, 'use_eviltwin', False)
    monkeypatch.setattr(Configuration, 'monitor_attacks', False)
    monkeypatch.setattr(Configuration, 'wpasec_enabled', False)
    validate(Configuration)


def test_channel_999_is_rejected(monkeypatch):
    with pytest.raises(WifiteError) as caught:
        _validate_with('999', monkeypatch)

    message = str(caught.value)
    assert '999' in message
    assert '1-233' in message


def test_channel_range_that_cannot_exist_is_rejected(monkeypatch):
    with pytest.raises(WifiteError):
        _validate_with('200-300', monkeypatch)


def test_channel_list_and_range_accepted(monkeypatch):
    for spec in ('6', '1,3-6', '1-11'):
        _validate_with(spec, monkeypatch)


def test_band_suffixed_channel_accepted(monkeypatch):
    for spec in ('1a', '36b', '5c'):
        _validate_with(spec, monkeypatch)


def test_no_channel_skips_validation(monkeypatch):
    _validate_with(None, monkeypatch)