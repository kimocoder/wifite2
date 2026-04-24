#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WPA3-SAE Detection and Classification Module

This module provides functionality to detect and classify WPA3-SAE capabilities
of wireless networks, including transition mode detection, PMF status, and
Dragonblood vulnerability indicators.
"""

from typing import Dict, List, Any, Optional


class WPA3Detector:
    """
    Detects and classifies WPA3-SAE capabilities of wireless targets.
    
    This class provides static methods to analyze target information and
    determine WPA3 support, transition mode, PMF status, and supported
    SAE groups.
    
    Performance optimizations:
    - Caches detection results in target.wpa3_info
    - Minimizes string operations and attribute access
    - Uses efficient parsing with early returns
    """

    # PMF Status Constants
    PMF_DISABLED = 'disabled'
    PMF_OPTIONAL = 'optional'
    PMF_REQUIRED = 'required'

    # Known vulnerable SAE groups (Dragonblood)
    VULNERABLE_SAE_GROUPS = [22, 23, 24]  # Groups susceptible to timing attacks
    
    # Default SAE group (most common)
    DEFAULT_SAE_GROUP = 19

    @staticmethod
    def detect_wpa3_capability(target, use_cache: bool = True) -> Dict[str, Any]:
        """
        Detect WPA3 capability from target beacon/probe response.
        
        Analyzes the target's encryption and authentication fields to determine
        WPA3 support, transition mode, PMF status, and other WPA3-related
        capabilities.
        
        Performance optimizations:
        - Returns cached results if available (unless use_cache=False)
        - Performs detection in single pass to minimize attribute access
        - Uses efficient string operations
        
        Args:
            target: Target object containing encryption and authentication info
            use_cache: If True, return cached results from target.wpa3_info if available
            
        Returns:
            Dictionary containing:
                - has_wpa3 (bool): True if WPA3 is supported
                - has_wpa2 (bool): True if WPA2 is supported
                - is_transition (bool): True if both WPA2 and WPA3 are supported
                - pmf_status (str): 'required', 'optional', or 'disabled'
                - sae_groups (List[int]): List of supported SAE groups
                - dragonblood_vulnerable (bool): True if vulnerable indicators detected
        """
        # Return cached results if available and caching is enabled
        if use_cache and hasattr(target, 'wpa3_info') and target.wpa3_info is not None:
            return target.wpa3_info.to_dict()
        
        # Perform detection in a single pass to minimize overhead
        # Cache string values to avoid repeated attribute access
        full_enc = getattr(target, 'full_encryption_string', '')
        full_auth = getattr(target, 'full_authentication_string', '')
        primary_enc = getattr(target, 'primary_encryption', '')
        primary_auth = getattr(target, 'primary_authentication', '')
        
        # Check for WPA3 and WPA2 support using cached strings
        has_wpa3 = ('WPA3' in full_enc or primary_enc == 'WPA3' or 
                    'SAE' in full_auth or primary_auth == 'SAE')
        has_wpa2 = ('WPA2' in full_enc or primary_enc == 'WPA2' or 
                    'PSK' in full_auth)
        
        # Early return for non-WPA3 targets to minimize overhead
        if not has_wpa3:
            return {
                'has_wpa3': False,
                'has_wpa2': has_wpa2,
                'is_transition': False,
                'pmf_status': WPA3Detector.PMF_DISABLED,
                'sae_groups': [],
                'dragonblood_vulnerable': False
            }
        
        # Determine if this is a transition mode network
        is_transition = has_wpa2
        
        # Determine PMF status efficiently based on WPA3 mode
        if is_transition:
            pmf_status = WPA3Detector.PMF_OPTIONAL
        else:
            # WPA3-only networks require PMF by specification
            pmf_status = WPA3Detector.PMF_REQUIRED
        
        # Get supported SAE groups from RSN IE if available, otherwise default
        sae_groups = WPA3Detector._probe_sae_groups(target)
        
        # Check for Dragonblood vulnerability
        # Only vulnerable groups 22-24 are susceptible
        dragonblood_vulnerable = any(g in WPA3Detector.VULNERABLE_SAE_GROUPS 
                                     for g in sae_groups)
        
        return {
            'has_wpa3': has_wpa3,
            'has_wpa2': has_wpa2,
            'is_transition': is_transition,
            'pmf_status': pmf_status,
            'sae_groups': sae_groups,
            'dragonblood_vulnerable': dragonblood_vulnerable
        }

    @staticmethod
    def _probe_sae_groups(target) -> List[int]:
        """
        Probe SAE groups advertised by the target.

        Attempts to read SAE group information from the target object's
        attributes (populated from beacon/probe-response parsing), falling
        back to the default group (19) when not available.

        Args:
            target: Target object (may contain sae_groups attribute)

        Returns:
            List of SAE group numbers.  Defaults to [19] when unavailable.
        """
        # Check if target already has SAE group information
        sae_groups = getattr(target, 'sae_groups', None)
        if sae_groups and isinstance(sae_groups, list) and len(sae_groups) > 0:
            return sae_groups

        # Try to extract from target's information elements if present
        # (populated by airodump/tshark parsers when available)
        rsn_ie = getattr(target, 'rsn_information', None)
        if rsn_ie and isinstance(rsn_ie, str):
            groups = WPA3Detector._parse_sae_groups_from_rsn(rsn_ie)
            if groups:
                return groups

        # Default to Group 19 (256-bit random ECP – most common WPA3 group)
        return [WPA3Detector.DEFAULT_SAE_GROUP]

    @staticmethod
    def _parse_sae_groups_from_rsn(rsn_info: str) -> List[int]:
        """
        Parse SAE groups from a RSN information element string.

        Args:
            rsn_info: RSN information element as hex string or human-readable string

        Returns:
            List of SAE group numbers, empty if none found.
        """
        import re
        groups: List[int] = []

        # Match patterns like "Group: 19" or "SAE Group: 22, 19"
        for match in re.finditer(r'\b(?:SAE\s+)?[Gg]roup[s]?\s*:?\s*(\d+(?:\s*,\s*\d+)*)', rsn_info):
            for part in match.group(1).split(','):
                try:
                    groups.append(int(part.strip()))
                except ValueError:
                    pass

        return groups

    @staticmethod
    def identify_transition_mode(target) -> bool:
        """
        Check if target supports both WPA2 and WPA3 (transition mode).
        
        Transition mode networks allow clients to connect using either WPA2
        or WPA3, making them vulnerable to downgrade attacks.
        
        Performance: Uses cached wpa3_info if available.
        
        Args:
            target: Target object to check
            
        Returns:
            True if target supports both WPA2 and WPA3, False otherwise
        """
        # Use cached info if available
        if hasattr(target, 'wpa3_info') and target.wpa3_info is not None:
            return target.wpa3_info.is_transition
        
        # Fallback to detection
        wpa3_info = WPA3Detector.detect_wpa3_capability(target)
        return wpa3_info['is_transition']

    @staticmethod
    def check_pmf_status(target) -> str:
        """
        Determine PMF (Protected Management Frames) status.
        
        PMF status affects attack strategies:
        - 'required': Deauth attacks won't work, must use passive capture
        - 'optional': Deauth attacks may work
        - 'disabled': Deauth attacks will work
        
        Performance: Uses cached wpa3_info if available.
        
        Args:
            target: Target object to check
            
        Returns:
            'required', 'optional', or 'disabled'
        """
        # Use cached info if available
        if hasattr(target, 'wpa3_info') and target.wpa3_info is not None:
            return target.wpa3_info.pmf_status
        
        # Fallback to detection
        wpa3_info = WPA3Detector.detect_wpa3_capability(target)
        return wpa3_info['pmf_status']

    @staticmethod
    def get_supported_sae_groups(target) -> List[int]:
        """
        Extract supported SAE groups from target information.
        
        SAE groups define the elliptic curve used for authentication.
        Common groups:
        - Group 19: 256-bit random ECP group (most common)
        - Group 20: 384-bit random ECP group
        - Group 21: 521-bit random ECP group
        - Groups 22-24: Vulnerable to Dragonblood attacks
        
        Performance: Uses cached wpa3_info if available.
        
        Args:
            target: Target object to analyze
            
        Returns:
            List of supported SAE group numbers. Returns [19] as default
            if WPA3 is detected but specific groups cannot be determined.
        """
        # Use cached info if available
        if hasattr(target, 'wpa3_info') and target.wpa3_info is not None:
            return target.wpa3_info.sae_groups
        
        # Fallback to detection
        wpa3_info = WPA3Detector.detect_wpa3_capability(target)
        return wpa3_info['sae_groups']

    @staticmethod
    def _has_wpa3(target) -> bool:
        """
        Check if target supports WPA3.
        
        Optimized to minimize attribute access and string operations.
        
        Args:
            target: Target object to check
            
        Returns:
            True if WPA3 is supported
        """
        # Check full encryption string for WPA3 (most reliable)
        full_enc = getattr(target, 'full_encryption_string', '')
        if 'WPA3' in full_enc:
            return True
        
        # Check primary encryption
        if getattr(target, 'primary_encryption', '') == 'WPA3':
            return True
        
        # Check authentication for SAE (WPA3's authentication method)
        full_auth = getattr(target, 'full_authentication_string', '')
        if 'SAE' in full_auth:
            return True
        
        # Check primary authentication
        if getattr(target, 'primary_authentication', '') == 'SAE':
            return True
        
        return False

    @staticmethod
    def _has_wpa2(target) -> bool:
        """
        Check if target supports WPA2.
        
        Optimized to minimize attribute access and string operations.
        
        Args:
            target: Target object to check
            
        Returns:
            True if WPA2 is supported
        """
        # Check full encryption string for WPA2 (most reliable)
        full_enc = getattr(target, 'full_encryption_string', '')
        if 'WPA2' in full_enc:
            return True
        
        # Check primary encryption
        if getattr(target, 'primary_encryption', '') == 'WPA2':
            return True
        
        # Check authentication for PSK (WPA2's common authentication method)
        # Note: PSK can also be used with WPA, but in context of WPA3 detection,
        # if we see PSK alongside SAE, it indicates transition mode
        full_auth = getattr(target, 'full_authentication_string', '')
        if 'PSK' in full_auth:
            return True
        
        return False

    @staticmethod
    def _check_dragonblood_vulnerability(sae_groups: List[int], has_wpa3: bool) -> bool:
        """
        Check for known Dragonblood vulnerability indicators.
        
        Dragonblood vulnerabilities (CVE-2019-13377 and related) affect certain
        SAE group configurations and implementations.
        
        Args:
            sae_groups: List of supported SAE groups
            has_wpa3: Whether the target supports WPA3
            
        Returns:
            True if vulnerability indicators are detected
        """
        if not has_wpa3:
            return False
        
        # Check if any vulnerable groups are supported
        for group in sae_groups:
            if group in WPA3Detector.VULNERABLE_SAE_GROUPS:
                return True
        
        return False


class WPA3Info:
    """
    Data class to store WPA3 capability information for a target.
    
    This class encapsulates all WPA3-related information detected for a
    wireless target, making it easy to store and retrieve this data.
    """
    
    def __init__(self, has_wpa3: bool = False, has_wpa2: bool = False,
                 is_transition: bool = False, pmf_status: str = WPA3Detector.PMF_DISABLED,
                 sae_groups: Optional[List[int]] = None,
                 dragonblood_vulnerable: bool = False):
        """
        Initialize WPA3Info object.
        
        Args:
            has_wpa3: True if WPA3 is supported
            has_wpa2: True if WPA2 is supported
            is_transition: True if both WPA2 and WPA3 are supported
            pmf_status: 'required', 'optional', or 'disabled'
            sae_groups: List of supported SAE groups
            dragonblood_vulnerable: True if vulnerable indicators detected
        """
        self.has_wpa3 = has_wpa3
        self.has_wpa2 = has_wpa2
        self.is_transition = is_transition
        self.pmf_status = pmf_status
        self.sae_groups = sae_groups if sae_groups is not None else []
        self.dragonblood_vulnerable = dragonblood_vulnerable
    
    def get(self, key: str, default=None):
        """
        Get attribute value by key (dict-like interface for backward compatibility).
        
        Args:
            key: Attribute name
            default: Default value if attribute doesn't exist
            
        Returns:
            Attribute value or default
        """
        return getattr(self, key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize WPA3Info to dictionary for storage.
        
        Returns:
            Dictionary representation of WPA3Info
        """
        return {
            'has_wpa3': self.has_wpa3,
            'has_wpa2': self.has_wpa2,
            'is_transition': self.is_transition,
            'pmf_status': self.pmf_status,
            'sae_groups': self.sae_groups,
            'dragonblood_vulnerable': self.dragonblood_vulnerable
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WPA3Info':
        """
        Deserialize WPA3Info from dictionary.
        
        Args:
            data: Dictionary containing WPA3Info data
            
        Returns:
            WPA3Info object
        """
        return cls(
            has_wpa3=data.get('has_wpa3', False),
            has_wpa2=data.get('has_wpa2', False),
            is_transition=data.get('is_transition', False),
            pmf_status=data.get('pmf_status', WPA3Detector.PMF_DISABLED),
            sae_groups=data.get('sae_groups', []),
            dragonblood_vulnerable=data.get('dragonblood_vulnerable', False)
        )
    
    def __repr__(self) -> str:
        """String representation of WPA3Info."""
        return (f"WPA3Info(has_wpa3={self.has_wpa3}, has_wpa2={self.has_wpa2}, "
                f"is_transition={self.is_transition}, pmf_status={self.pmf_status}, "
                f"sae_groups={self.sae_groups}, dragonblood_vulnerable={self.dragonblood_vulnerable})")
