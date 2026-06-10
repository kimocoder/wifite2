#!/usr/bin/env python

"""
Performance benchmark for WPA3 detection optimization.

This test demonstrates the performance improvements from caching
and efficient parsing.
"""

import unittest
import time
from wifite.model.target import Target
from wifite.util.wpa3 import WPA3Detector


class TestWPA3DetectionPerformance(unittest.TestCase):
    """Performance benchmarks for WPA3 detection."""

    def setUp(self):
        """Create test targets."""
        # WPA3 transition mode target
        self.wpa3_transition_fields = [
            'AA:BB:CC:DD:EE:FF',
            '2024-01-01 00:00:00',
            '2024-01-01 00:00:01',
            '6',
            '54',
            'WPA2 WPA3',
            'CCMP',
            'PSK SAE',
            '-50',
            '10',
            '0',
            '0.0.0.0',
            '8',
            'TestNet',
            ''
        ]
        
        # WPA2-only target
        self.wpa2_only_fields = [
            'BB:BB:CC:DD:EE:FF',
            '2024-01-01 00:00:00',
            '2024-01-01 00:00:01',
            '6',
            '54',
            'WPA2',
            'CCMP',
            'PSK',
            '-50',
            '10',
            '0',
            '0.0.0.0',
            '8',
            'TestNet2',
            ''
        ]

    def test_cache_performance_improvement(self):
        """Benchmark cache performance improvement."""
        target = Target(self.wpa3_transition_fields)
        iterations = 1000
        
        # Measure time without cache (fresh detection each time)
        start_time = time.time()
        for _ in range(iterations):
            WPA3Detector.detect_wpa3_capability(target, use_cache=False)
        no_cache_time = time.time() - start_time
        
        # Set cache once
        wpa3_info_dict = WPA3Detector.detect_wpa3_capability(target, use_cache=False)
        from wifite.util.wpa3 import WPA3Info
        target.wpa3_info = WPA3Info.from_dict(wpa3_info_dict)
        
        # Measure time with cache
        start_time = time.time()
        for _ in range(iterations):
            WPA3Detector.detect_wpa3_capability(target, use_cache=True)
        cache_time = time.time() - start_time
        
        # Cache should be significantly faster
        speedup = no_cache_time / cache_time if cache_time > 0 else float('inf')
        
        print(f"\nCache Performance Benchmark ({iterations} iterations):")
        print(f"  Without cache: {no_cache_time:.4f}s")
        print(f"  With cache:    {cache_time:.4f}s")
        print(f"  Speedup:       {speedup:.2f}x")
        
        # Cache should be at least 2x faster
        self.assertGreater(speedup, 2.0, 
                          f"Cache speedup {speedup:.2f}x is less than expected 2x")

    def test_early_return_performance(self):
        """Benchmark early return optimization for WPA2-only targets."""
        wpa2_target = Target(self.wpa2_only_fields)
        wpa3_target = Target(self.wpa3_transition_fields)
        iterations = 1000
        
        # Measure WPA2-only detection (should be faster with early return)
        start_time = time.time()
        for _ in range(iterations):
            WPA3Detector.detect_wpa3_capability(wpa2_target, use_cache=False)
        wpa2_time = time.time() - start_time
        
        # Measure WPA3 detection (full processing)
        start_time = time.time()
        for _ in range(iterations):
            WPA3Detector.detect_wpa3_capability(wpa3_target, use_cache=False)
        wpa3_time = time.time() - start_time
        
        print(f"\nEarly Return Benchmark ({iterations} iterations):")
        print(f"  WPA2-only (early return): {wpa2_time:.4f}s")
        print(f"  WPA3 (full processing):   {wpa3_time:.4f}s")
        print(f"  Ratio:                    {wpa3_time/wpa2_time:.2f}x")
        
        # WPA2-only should be faster or similar (early return optimization)
        # Allow some variance due to system load
        self.assertLessEqual(wpa2_time, wpa3_time * 1.5,
                            "WPA2-only detection should benefit from early return")

    def test_helper_method_cache_usage(self):
        """Benchmark helper methods using cache vs fresh detection."""
        target = Target(self.wpa3_transition_fields)
        iterations = 1000
        
        # Without cache - helper methods trigger full detection
        start_time = time.time()
        for _ in range(iterations):
            target.wpa3_info = None  # Clear cache
            WPA3Detector.identify_transition_mode(target)
            WPA3Detector.check_pmf_status(target)
            WPA3Detector.get_supported_sae_groups(target)
        no_cache_time = time.time() - start_time
        
        # With cache - helper methods use cached data
        wpa3_info_dict = WPA3Detector.detect_wpa3_capability(target, use_cache=False)
        from wifite.util.wpa3 import WPA3Info
        target.wpa3_info = WPA3Info.from_dict(wpa3_info_dict)
        
        start_time = time.time()
        for _ in range(iterations):
            WPA3Detector.identify_transition_mode(target)
            WPA3Detector.check_pmf_status(target)
            WPA3Detector.get_supported_sae_groups(target)
        cache_time = time.time() - start_time
        
        speedup = no_cache_time / cache_time if cache_time > 0 else float('inf')
        
        print(f"\nHelper Method Cache Benchmark ({iterations} iterations):")
        print(f"  Without cache: {no_cache_time:.4f}s")
        print(f"  With cache:    {cache_time:.4f}s")
        print(f"  Speedup:       {speedup:.2f}x")
        
        # Cache should provide significant speedup
        self.assertGreater(speedup, 2.0,
                          f"Helper method cache speedup {speedup:.2f}x is less than expected")


if __name__ == '__main__':
    unittest.main()
