#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Run-scoped handover of hcxdumptool captures between attacks.

One hcxdumptool session harvests both PMKID and EAPOL material. PMKID runs
first, so it publishes its capture here and the handshake attack reuses it
instead of paying for a second capture and a second monitor-mode round trip.
"""

import os

from ..config import Configuration
from ..util.logger import log_debug

_captures = {}


def _key(bssid):
    return (bssid or '').upper()


def register(bssid, capture_path):
    """Publish ``capture_path`` for ``bssid``; returns the stored path or None."""
    if not bssid or not capture_path:
        return None

    try:
        if not os.path.exists(capture_path) or os.path.getsize(capture_path) == 0:
            return None
    except OSError:
        return None

    target = Configuration.temp(
        'shared_hcx_%s.pcapng' % bssid.lower().replace(':', ''))
    if os.path.abspath(capture_path) != os.path.abspath(target):
        try:
            from shutil import copyfile
            copyfile(capture_path, target)
        except OSError as error:
            log_debug('CaptureCache', 'could not publish capture: %s' % error)
            return None

    _captures[_key(bssid)] = target
    log_debug('CaptureCache', 'published %s for %s' % (target, bssid))
    return target


def get(bssid):
    """Return the published capture for ``bssid`` if it still exists."""
    path = _captures.get(_key(bssid))
    if path and os.path.exists(path):
        return path
    return None


def discard(bssid):
    _captures.pop(_key(bssid), None)


def clear():
    for path in list(_captures.values()):
        try:
            os.remove(path)
        except OSError:
            pass
    _captures.clear()