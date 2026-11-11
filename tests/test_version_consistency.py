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


def test_fallback_version_matches_pyproject():
    """_get_version() falls back to a literal when no package metadata exists."""
    with patch('importlib.metadata.version', side_effect=Exception('no metadata')):
        fallback = config_module._get_version()

    assert fallback == _pyproject_version()


def test_setup_py_matches_pyproject():
    assert _setup_py_version() == _pyproject_version()