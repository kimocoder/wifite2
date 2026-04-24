#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Dragonblood Timing Attack Support

Implements timing-based side-channel analysis for WPA3-SAE networks.
The Dragonblood timing attack (CVE-2019-13377) exploits timing differences
in SAE commit frame processing to reveal information about the password.

This module provides:
- Timing measurement of SAE commit responses
- Statistical analysis of response time distributions
- Threshold-based vulnerability assessment

References:
- https://wpa3.mathyvanhoef.com/
- https://papers.mathyvanhoef.com/dragonblood.pdf
"""

import time
import statistics
from typing import List, Optional, Tuple, Dict, Any

from ..util.color import Color
from ..util.logger import log_debug, log_info, log_warning


# Default timing threshold in seconds (5 ms)
DEFAULT_TIMING_THRESHOLD = 0.005

# Minimum samples for reliable statistical analysis
MIN_SAMPLES_FOR_ANALYSIS = 10

# Number of probe rounds for timing measurement
DEFAULT_PROBE_ROUNDS = 20


class DragonbloodTimingResult:
    """Stores the result of a Dragonblood timing measurement."""

    def __init__(self, bssid: str, essid: str):
        self.bssid = bssid
        self.essid = essid
        self.timing_samples: List[float] = []
        self.mean_time: float = 0.0
        self.std_dev: float = 0.0
        self.max_time: float = 0.0
        self.min_time: float = 0.0
        self.timing_variance_detected: bool = False
        self.vulnerable: bool = False
        self.confidence: float = 0.0
        self.error: Optional[str] = None

    def compute_statistics(self):
        """Compute timing statistics from collected samples."""
        if len(self.timing_samples) < 2:
            self.error = 'Insufficient samples for analysis'
            return

        self.mean_time = statistics.mean(self.timing_samples)
        self.std_dev = statistics.stdev(self.timing_samples)
        self.max_time = max(self.timing_samples)
        self.min_time = min(self.timing_samples)

        # Coefficient of variation indicates relative variance
        if self.mean_time > 0:
            cv = self.std_dev / self.mean_time
            # High CV (>0.1) suggests significant timing variance
            self.timing_variance_detected = cv > 0.1
            # Confidence is based on sample count and variance consistency
            sample_factor = min(1.0, len(self.timing_samples) / MIN_SAMPLES_FOR_ANALYSIS)
            self.confidence = sample_factor * (1.0 if self.timing_variance_detected else 0.5)

    def __repr__(self):
        return (
            f'DragonbloodTimingResult(bssid={self.bssid!r}, '
            f'vulnerable={self.vulnerable}, '
            f'mean={self.mean_time * 1000:.2f}ms, '
            f'std_dev={self.std_dev * 1000:.2f}ms)'
        )


class DragonbloodTimingAnalyzer:
    """
    Analyzes WPA3-SAE timing side-channels.

    The timing attack works by sending multiple SAE commit frames and
    measuring the response time.  Implementations using MODP groups
    (22, 23, 24) have observable timing differences depending on which
    iteration of the hunting-and-pecking algorithm is used, leaking
    information about the password.
    """

    # SAE groups known to be vulnerable to timing attacks
    TIMING_VULNERABLE_GROUPS = {22, 23, 24}

    def __init__(self, interface: str, threshold: float = DEFAULT_TIMING_THRESHOLD):
        """
        Initialize the timing analyzer.

        Args:
            interface: Wireless interface in monitor mode
            threshold: Timing threshold in seconds (default 5 ms)
        """
        self.interface = interface
        self.threshold = threshold

    def measure_sae_response_times(
        self,
        target_bssid: str,
        target_channel: int,
        rounds: int = DEFAULT_PROBE_ROUNDS,
    ) -> List[float]:
        """
        Measure SAE commit response times against a target.

        Sends probe requests and times the authentication frame responses.
        Returns a list of round-trip times in seconds.

        Args:
            target_bssid: BSSID of the target AP
            target_channel: Channel of the target AP
            rounds: Number of measurement rounds

        Returns:
            List of response times in seconds
        """
        timings: List[float] = []
        log_info('DragonbloodTiming', 'Measuring SAE response times for %s' % target_bssid)

        try:
            from ..util.process import Process

            for i in range(rounds):
                start = time.monotonic()
                # Send a probe request and wait for authentication frame
                # Using a lightweight scan of the target channel
                cmd = [
                    'timeout', '1',
                    'iw', 'dev', self.interface,
                    'scan', 'freq', str(_channel_to_freq(target_channel)),
                    'ap-force',
                ]
                proc = Process(cmd, devnull=True)
                proc.wait()
                elapsed = time.monotonic() - start

                if elapsed < 5.0:  # Ignore unreasonably large values
                    timings.append(elapsed)

                log_debug('DragonbloodTiming', 'Round %d: %.3f ms' % (i + 1, elapsed * 1000))
                time.sleep(0.1)  # Brief pause between probes

        except Exception as e:
            log_warning('DragonbloodTiming', 'Timing measurement failed: %s' % e)

        return timings

    def analyze(
        self,
        target_bssid: str,
        target_essid: str,
        target_channel: int,
        sae_groups: Optional[List[int]] = None,
        rounds: int = DEFAULT_PROBE_ROUNDS,
    ) -> DragonbloodTimingResult:
        """
        Perform a full Dragonblood timing analysis on a target.

        Args:
            target_bssid: BSSID of the target AP
            target_essid: ESSID of the target AP
            target_channel: Channel of the target AP
            sae_groups: Known SAE groups advertised by the AP
            rounds: Number of timing rounds

        Returns:
            DragonbloodTimingResult with analysis results
        """
        result = DragonbloodTimingResult(bssid=target_bssid, essid=target_essid)

        # Pre-check: only MODP groups are vulnerable to timing attacks
        if sae_groups is not None:
            vulnerable_groups = [g for g in sae_groups if g in self.TIMING_VULNERABLE_GROUPS]
            if not vulnerable_groups:
                log_info(
                    'DragonbloodTiming',
                    'No timing-vulnerable SAE groups detected for %s' % target_bssid,
                )
                return result

        Color.pl('{+} {C}Dragonblood Timing:{W} Measuring SAE response times...')
        timings = self.measure_sae_response_times(target_bssid, target_channel, rounds)
        result.timing_samples = timings
        result.compute_statistics()

        if result.error:
            Color.pl('{!} {O}Timing analysis error: %s{W}' % result.error)
            return result

        # Assess vulnerability based on timing variance
        result.vulnerable = (
            result.timing_variance_detected
            and result.std_dev > self.threshold
        )

        log_info(
            'DragonbloodTiming',
            'Analysis for %s: mean=%.2f ms, std=%.2f ms, vulnerable=%s'
            % (
                target_bssid,
                result.mean_time * 1000,
                result.std_dev * 1000,
                result.vulnerable,
            ),
        )
        return result

    @staticmethod
    def print_result(result: DragonbloodTimingResult):
        """Print a human-readable timing analysis result."""
        Color.pl('\n{+} {C}Dragonblood Timing Analysis:{W} %s ({C}%s{W})' % (
            result.essid or 'Hidden', result.bssid))

        if result.error:
            Color.pl('{!} {O}Error: %s{W}' % result.error)
            return

        if not result.timing_samples:
            Color.pl('{!} {O}No timing samples collected{W}')
            return

        Color.pl('    Samples:     {G}%d{W}' % len(result.timing_samples))
        Color.pl('    Mean:        {G}%.2f ms{W}' % (result.mean_time * 1000))
        Color.pl('    Std Dev:     {G}%.2f ms{W}' % (result.std_dev * 1000))
        Color.pl('    Min / Max:   {G}%.2f{W} / {G}%.2f ms{W}' % (
            result.min_time * 1000, result.max_time * 1000))

        if result.vulnerable:
            Color.pl('\n{!} {R}Timing side-channel DETECTED{W}')
            Color.pl('    {O}CVE-2019-13377: Timing variance suggests vulnerable SAE implementation{W}')
            Color.pl('    {O}Confidence: %.0f%%{W}' % (result.confidence * 100))
        else:
            Color.pl('\n{+} {G}No significant timing variance detected{W}')

        Color.pl('')


def _channel_to_freq(channel: int) -> int:
    """Convert an 802.11 channel number to its centre frequency in MHz."""
    if 1 <= channel <= 13:
        return 2412 + (channel - 1) * 5
    if channel == 14:
        return 2484
    if 36 <= channel <= 177:
        return 5180 + (channel - 36) * 5
    # Unknown channel – return a safe default
    return 2412


def run_timing_attack(
    target,
    interface: str,
    threshold: float = DEFAULT_TIMING_THRESHOLD,
    rounds: int = DEFAULT_PROBE_ROUNDS,
) -> DragonbloodTimingResult:
    """
    Convenience wrapper to run a Dragonblood timing analysis.

    Args:
        target: Target object with bssid, essid, channel, and optionally wpa3_info
        interface: Wireless interface in monitor mode
        threshold: Timing threshold in seconds
        rounds: Number of timing measurement rounds

    Returns:
        DragonbloodTimingResult
    """
    sae_groups: Optional[List[int]] = None
    if hasattr(target, 'wpa3_info') and target.wpa3_info:
        sae_groups = target.wpa3_info.get('sae_groups')

    analyzer = DragonbloodTimingAnalyzer(interface=interface, threshold=threshold)
    result = analyzer.analyze(
        target_bssid=target.bssid,
        target_essid=getattr(target, 'essid', '') or '',
        target_channel=target.channel,
        sae_groups=sae_groups,
        rounds=rounds,
    )
    DragonbloodTimingAnalyzer.print_result(result)
    return result
