#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from .dependency import Dependency


def _check_iface(name):
    """Validate interface name before passing to subprocess (SEC-010)."""
    from ..config.validators import validate_interface_name
    validate_interface_name(name)


class Ip(Dependency):
    dependency_required = True
    dependency_name = 'ip'
    dependency_url = 'apt install iproute2'
    dependency_packages = {
        'apt': 'iproute2', 'pacman': 'iproute2', 'dnf': 'iproute',
        'apk': 'iproute2',
    }
    dependency_category = Dependency.CATEGORY_CORE

    @classmethod
    def up(cls, interface):
        """Put interface up through the single state owner."""
        from ..config import Configuration

        _check_iface(interface)
        if not Configuration.get_interface_manager().set_interface_up(interface, True):
            raise Exception('Error putting interface %s up' % interface)

    @classmethod
    def down(cls, interface):
        """Put interface down through the single state owner."""
        from ..config import Configuration

        _check_iface(interface)
        if not Configuration.get_interface_manager().set_interface_up(interface, False):
            raise Exception('Error putting interface %s down' % interface)

    @classmethod
    def get_mac(cls, interface):
        from ..util.process import Process

        _check_iface(interface)
        (out, err) = Process.call(f'ip link show {interface}')
        if match := re.search(r'([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2}', out):
            return match[0].replace('-', ':')

        raise Exception(f'Could not find the mac address for {interface}')
