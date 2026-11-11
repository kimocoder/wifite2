"""The version must be declared identically everywhere."""

import re
import tomllib
from pathlib import Path
from unittest.mock import patch

import wifite.config as config_module

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version():
    data = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    return data['project']['version']


def _setup_py_version():
    text = (ROOT / 'setup.py').read_text(encoding='utf-8')
    match = re.search(r"version='([^']+)'", text)
    assert match, 'setup.py has no version= declaration'
    return match.group(1)


def test_source_checkout_version_beats_stale_metadata():
    """A leftover wifite2.egg-info in the clone must not shadow pyproject."""
    with patch('importlib.metadata.version', return_value='2.9.9b0'):
        assert config_module._get_version() == _pyproject_version()


def test_source_version_matches_pyproject():
    assert config_module._source_version() == _pyproject_version()


def test_fallback_version_matches_pyproject():
    """_get_version() falls back to a literal when no metadata exists."""
    with patch.object(config_module, '_source_version', return_value=None), \
            patch('importlib.metadata.version', side_effect=Exception('no metadata')):
        fallback = config_module._get_version()

    assert fallback == _pyproject_version()


def test_installed_metadata_used_without_checkout():
    with patch.object(config_module, '_source_version', return_value=None), \
            patch('importlib.metadata.version', return_value='9.9.9'):
        assert config_module._get_version() == '9.9.9'


def test_setup_py_matches_pyproject():
    assert _setup_py_version() == _pyproject_version()