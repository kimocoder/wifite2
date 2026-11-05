#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unit tests for SAEHandshake class.

Tests frame parsing, hashcat conversion, and validation.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import tempfile

import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifite.model.sae_handshake import SAEHandshake
from wifite.util.process import Process

pytestmark = pytest.mark.timeout(30)

BSSID_HEX = 'aabbccddeeff'
ESSID_HEX = '5465737457504133'  # 'TestWPA3'
MATCHING_HASH = (
    f'WPA*01*0123456789abcdef0123456789abcdef*{BSSID_HEX}'
    f'*112233445566*{ESSID_HEX}***'
)


def mock_hcxpcapngtool(mock_process_class, write_hashes=True):
    """Make the mocked hcxpcapngtool write one matching record to -o."""
    mock_process_class.exists.return_value = True

    def fake_process(command, devnull=False):
        instance = Mock()

        def wait():
            if write_hashes:
                target = command[command.index('-o') + 1]
                with open(target, 'w') as fh:
                    fh.write(MATCHING_HASH + '\n')
            return 0

        instance.wait.side_effect = wait
        return instance

    mock_process_class.side_effect = fake_process
    return mock_process_class


class TestSAEHandshake(unittest.TestCase):
    """Test suite for SAEHandshake functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary capture file for testing
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.cap')
        self.temp_file.close()
        self.capfile = self.temp_file.name
        self.bssid = 'AA:BB:CC:DD:EE:FF'
        self.essid = 'TestWPA3'

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.capfile):
            os.remove(self.capfile)

    def test_initialization(self):
        """Test SAEHandshake initialization."""
        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        
        self.assertEqual(hs.capfile, self.capfile)
        self.assertEqual(hs.bssid, self.bssid)
        self.assertEqual(hs.essid, self.essid)
        self.assertEqual(hs.commit_frames, [])
        self.assertEqual(hs.confirm_frames, [])
        self.assertIsNone(hs.sae_data)
        self.assertIsNone(hs.hash_file)

    def test_initialization_without_essid(self):
        """Test SAEHandshake initialization without ESSID."""
        hs = SAEHandshake(self.capfile, self.bssid)
        
        self.assertEqual(hs.capfile, self.capfile)
        self.assertEqual(hs.bssid, self.bssid)
        self.assertIsNone(hs.essid)

    @patch('wifite.tools.hcxdumptool.Process')
    def test_validate_with_hcxpcapngtool_success(self, mock_process_class):
        """Test validation with hcxpcapngtool when handshake is valid."""
        mock_hcxpcapngtool(mock_process_class)

        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        self.assertTrue(hs._validate_with_hcxpcapngtool())

    @patch('wifite.tools.hcxdumptool.Process')
    def test_validate_with_hcxpcapngtool_failure(self, mock_process_class):
        """Test validation with hcxpcapngtool when handshake is invalid."""
        mock_hcxpcapngtool(mock_process_class, write_hashes=False)

        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        self.assertFalse(hs._validate_with_hcxpcapngtool())

    @patch('wifite.tools.hcxdumptool.Process')
    def test_validate_with_hcxpcapngtool_not_installed(self, mock_process_class):
        """Test validation when hcxpcapngtool is not installed."""
        mock_process_class.exists.return_value = False

        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        self.assertFalse(hs._validate_with_hcxpcapngtool())

    @patch('wifite.model.sae_handshake.Tshark')
    @patch('wifite.model.sae_handshake.Process')
    def test_validate_with_tshark_success(self, mock_process_class, mock_tshark):
        """A complete handshake has both a Commit (seq 1) and Confirm (seq 2)."""
        # Mock Tshark.exists to return True
        mock_tshark.exists.return_value = True

        # Mock process output: auth-sequence numbers (1=Commit, 2=Confirm).
        mock_proc = Mock()
        mock_proc.stdout.return_value = '1\n1\n2\n2\n'
        mock_process_class.return_value = mock_proc

        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs._validate_with_tshark()

        self.assertTrue(result)

    @patch('wifite.model.sae_handshake.Tshark')
    @patch('wifite.model.sae_handshake.Process')
    def test_validate_with_tshark_commits_only(self, mock_process_class, mock_tshark):
        """Two Commits with no Confirm must NOT count as a complete handshake."""
        mock_tshark.exists.return_value = True

        # Only Commit (seq 1) frames — no Confirm (seq 2).
        mock_proc = Mock()
        mock_proc.stdout.return_value = '1\n1\n'
        mock_process_class.return_value = mock_proc

        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs._validate_with_tshark()

        self.assertFalse(result)

    @patch('wifite.model.sae_handshake.Tshark')
    @patch('wifite.model.sae_handshake.Process')
    def test_validate_with_tshark_failure(self, mock_process_class, mock_tshark):
        """Test validation with tshark when handshake is invalid."""
        # Mock Tshark.exists to return True
        mock_tshark.exists.return_value = True
        
        # Mock process execution with no frames
        mock_proc = Mock()
        mock_proc.stdout.return_value = ''
        mock_process_class.return_value = mock_proc
        
        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs._validate_with_tshark()
        
        self.assertFalse(result)

    @patch('wifite.model.sae_handshake.Tshark')
    def test_validate_with_tshark_not_installed(self, mock_tshark):
        """Test validation when tshark is not installed."""
        # Mock Tshark.exists to return False
        mock_tshark.exists.return_value = False
        
        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs._validate_with_tshark()
        
        self.assertFalse(result)

    @patch('wifite.model.sae_handshake.Tshark')
    @patch('wifite.model.sae_handshake.Process')
    def test_extract_sae_data_success(self, mock_process_class, mock_tshark):
        """Test SAE data extraction with valid frames."""
        # Mock Tshark.exists to return True
        mock_tshark.exists.return_value = True
        
        # Mock process execution with frame data
        mock_proc = Mock()
        mock_proc.stdout.return_value = (
            'AA:BB:CC:DD:EE:FF\t11:22:33:44:55:66\tAA:BB:CC:DD:EE:FF\t19\t1234567890.123\n'
            'AA:BB:CC:DD:EE:FF\tAA:BB:CC:DD:EE:FF\t11:22:33:44:55:66\t19\t1234567890.456\n'
        )
        mock_process_class.return_value = mock_proc
        
        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs.extract_sae_data()
        
        self.assertIsNotNone(result)
        self.assertEqual(result['bssid'], self.bssid)
        self.assertEqual(result['essid'], self.essid)
        self.assertEqual(result['frame_count'], 2)
        self.assertEqual(len(result['frames']), 2)

    @patch('wifite.model.sae_handshake.Tshark')
    def test_extract_sae_data_no_tshark(self, mock_tshark):
        """Test SAE data extraction when tshark is not available."""
        # Mock Tshark.exists to return False
        mock_tshark.exists.return_value = False
        
        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs.extract_sae_data()
        
        self.assertIsNone(result)

    @patch('wifite.model.sae_handshake.Tshark')
    @patch('wifite.model.sae_handshake.Process')
    def test_extract_sae_data_no_frames(self, mock_process_class, mock_tshark):
        """Test SAE data extraction with no frames."""
        # Mock Tshark.exists to return True
        mock_tshark.exists.return_value = True
        
        # Mock process execution with no output
        mock_proc = Mock()
        mock_proc.stdout.return_value = ''
        mock_process_class.return_value = mock_proc
        
        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs.extract_sae_data()
        
        self.assertIsNone(result)

    @patch('wifite.model.sae_handshake.Color')
    @patch('wifite.tools.hcxdumptool.Process')
    def test_convert_to_hashcat_success(self, mock_process_class, mock_color):
        """Test conversion to hashcat format."""
        mock_hcxpcapngtool(mock_process_class)

        output_file = f'{self.capfile}.22000'
        try:
            hs = SAEHandshake(self.capfile, self.bssid, self.essid)
            result = hs.convert_to_hashcat(output_file)

            self.assertEqual(result, output_file)
            self.assertEqual(hs.hash_file, output_file)
            with open(output_file) as fh:
                self.assertIn(MATCHING_HASH, fh.read())
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    @patch('wifite.model.sae_handshake.Color')
    @patch('wifite.tools.hcxdumptool.Process')
    def test_convert_to_hashcat_failure(self, mock_process_class, mock_color):
        """Test conversion to hashcat format when it fails."""
        mock_hcxpcapngtool(mock_process_class, write_hashes=False)

        output_file = f'{self.capfile}.22000'

        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs.convert_to_hashcat(output_file)

        self.assertIsNone(result)

    @patch('wifite.model.sae_handshake.Color')
    @patch('wifite.tools.hcxdumptool.Process')
    def test_convert_to_hashcat_no_tool(self, mock_process_class, mock_color):
        """Test conversion when hcxpcapngtool is not installed."""
        mock_process_class.exists.return_value = False

        hs = SAEHandshake(self.capfile, self.bssid, self.essid)
        result = hs.convert_to_hashcat()

        self.assertIsNone(result)

    @patch('wifite.model.sae_handshake.Color')
    @patch('wifite.tools.hcxdumptool.Process')
    def test_convert_to_hashcat_auto_filename(self, mock_process_class, mock_color):
        """Test conversion with auto-generated filename."""
        mock_hcxpcapngtool(mock_process_class)

        # Expected filename
        expected_file = f'sae_handshake_{self.essid}_{self.bssid.replace(":", "-")}.22000'

        try:
            hs = SAEHandshake(self.capfile, self.bssid, self.essid)
            result = hs.convert_to_hashcat()

            self.assertEqual(result, expected_file)
        finally:
            if os.path.exists(expected_file):
                os.remove(expected_file)

    def test_save_handshake(self):
        """Test saving handshake to directory."""
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        
        try:
            hs = SAEHandshake(self.capfile, self.bssid, self.essid)
            result = hs.save(temp_dir)
            
            expected_filename = f'sae_handshake_{self.essid}_{self.bssid.replace(":", "-")}.cap'
            expected_path = os.path.join(temp_dir, expected_filename)
            
            self.assertEqual(result, expected_path)
            self.assertTrue(os.path.exists(expected_path))
        finally:
            # Clean up
            import shutil
            shutil.rmtree(temp_dir)

    def test_check_tools(self):
        """Test tool availability checking."""
        tools = SAEHandshake.check_tools()
        
        self.assertIsInstance(tools, dict)
        self.assertIn('hcxpcapngtool', tools)
        self.assertIn('tshark', tools)
        self.assertIn('hashcat', tools)
        self.assertIsInstance(tools['hcxpcapngtool'], bool)
        self.assertIsInstance(tools['tshark'], bool)
        self.assertIsInstance(tools['hashcat'], bool)

    @patch('wifite.model.sae_handshake.Color')
    def test_print_tool_status(self, mock_color):
        """Test printing tool status."""
        # Should not raise any exceptions
        SAEHandshake.print_tool_status()
        
        # Verify Color.pl was called
        self.assertTrue(mock_color.pl.called)


if __name__ == '__main__':
    unittest.main()
