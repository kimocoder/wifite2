#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Run-scoped negative cache of exhausted (target, wordlist) pairs.

PMKID and handshake artifacts for the same BSSID share the passphrase, so a
wordlist that has been exhausted for one cannot crack the other. Remember the
miss and skip the duplicate run instead of hashing the same list twice.
"""

import os

_exhausted = set()


def _key(bssid, wordlist):
    return ((bssid or '').upper(), os.path.abspath(wordlist))


def is_exhausted(bssid, wordlist):
    """True when this wordlist already missed for this target in this run."""
    return _key(bssid, wordlist) in _exhausted


def mark_exhausted(bssid, wordlist):
    """Record that hashcat ran this wordlist to exhaustion for this target."""
    _exhausted.add(_key(bssid, wordlist))


def clear():
    _exhausted.clear()