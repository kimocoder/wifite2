#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Interop helpers for hcxdumptool / hcxtools 7.x and 8.x.

hcxpcapngtool dropped ``--bssid``/``--essid`` (filtering moved to
``hcxhashtool``), and hcxdumptool requires an explicit band suffix on
channel numbers. Both are shared by the two wrapper modules so the
behaviour cannot drift between them.
"""

import binascii

# hcxdumptool -c band suffixes.
BAND_24GHZ = 'a'
BAND_5GHZ = 'b'
BAND_6GHZ = 'c'

_HASH_TYPES = ('01', '02', '03', '04')


def channel_spec(channel):
    """Return an hcxdumptool ``-c`` value with its band suffix.

    hcxdumptool 7+ requires ``1a`` (2.4 GHz), ``36b`` (5 GHz) or ``5c``
    (6 GHz). A bare channel number is ambiguous between 2.4 and 6 GHz
    (both start at 1), so callers that know the band may pass a string
    such as ``'5c'`` and it is returned unchanged.
    """
    if channel is None:
        return None

    if isinstance(channel, str):
        value = channel.strip()
        if value and value[-1].lower() in (BAND_24GHZ, BAND_5GHZ, BAND_6GHZ):
            return value
        channel = int(value)

    number = int(channel)
    if number <= 0:
        # Airodump reports -1 when the channel could not be parsed.
        return str(number)
    if number <= 14:
        return f'{number}{BAND_24GHZ}'
    if number <= 177:
        return f'{number}{BAND_5GHZ}'
    return f'{number}{BAND_6GHZ}'


def _normalize_mac(mac):
    return mac.strip().lower().replace(':', '').replace('-', '')


def _essid_hex(essid):
    return binascii.hexlify(essid.encode('utf-8')).decode('ascii').lower()


def hash_line_matches(line, bssid=None, essid=None):
    """Return True when a mode-22000 line matches the given filters.

    A 22000 record is ``WPA*TYPE*PMKID/MIC*MAC_AP*MAC_CLIENT*ESSID*...``,
    so the AP MAC is field 3 and the hex-encoded ESSID is field 5.
    """
    fields = line.strip().split('*')
    if len(fields) < 6 or fields[0] != 'WPA' or fields[1] not in _HASH_TYPES:
        return False
    if bssid and fields[3].lower() != _normalize_mac(bssid):
        return False
    if essid and fields[5].lower() != _essid_hex(essid):
        return False
    return True


def filter_hash_lines(lines, bssid=None, essid=None):
    """Keep only well-formed WPA hash lines matching the filters."""
    return [line for line in lines if hash_line_matches(line, bssid, essid)]