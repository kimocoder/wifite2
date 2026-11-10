#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from ..config import Configuration


class Attack:
    """Contains functionality common to all attacks."""

    supervised = False
    scope = None

    def set_scope(self, scope):
        self.scope = scope

    def _cap_timeout(self, configured):
        if self.scope is None:
            return configured
        return min(configured, self.scope.remaining())

    def _check_scope(self):
        if self.scope is not None:
            self.scope.check()

    def _sleep_scope(self, seconds):
        if self.scope is not None:
            self.scope.sleep(min(seconds, self.scope.remaining()))
        else:
            time.sleep(seconds)

    @staticmethod
    def _get_target_wait():
        """Get target wait time, safely handling uninitialized Configuration."""
        timeout = Configuration.wpa_attack_timeout
        if timeout is None:
            return 60
        return min(60, timeout)

    def __init__(self, target):
        self.target = target
        self.scope = None

    def run(self):
        raise Exception('Unimplemented method: run')

    def wait_for_target(self, airodump, timeout=None):
        """Waits for target to appear in airodump.

        Args:
            airodump: Airodump instance to poll
            timeout: Optional bound in seconds; defaults to the configured
                     attack timeout. Callers inside a polling loop pass a
                     short value so the call does not block the loop.
        """
        target_wait = self._cap_timeout(
            timeout if timeout is not None else Attack._get_target_wait())
        start_time = time.monotonic()
        targets = airodump.get_targets(apply_filter=False)
        while len(targets) == 0:
            self._check_scope()
            if time.monotonic() - start_time > target_wait:
                raise Exception(f'Target did not appear after {target_wait} seconds, target may be out of range or turned off')
            self._sleep_scope(1)
            targets = airodump.get_targets()

        airodump_target = next((t for t in targets if t.bssid == self.target.bssid), None)

        if airodump_target is None:
            raise Exception(f'Could not find target ({self.target.bssid}) in airodump')

        return airodump_target
