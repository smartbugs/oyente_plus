"""Integration tests for file operations and external commands.

Tests moved from test_utils.py that involve real file I/O,
subprocess calls, and external tool integration.
"""

import json
import os
import tempfile
from unittest.mock import Mock
from unittest.mock import patch

import pytest

# Import utils module for file operation testing
from oyente import utils


@pytest.mark.integration
class TestFileOperations:
    """Test file operation utility functions with real I/O."""

    def test_split_dicts_creates_multiple_files(self):
        """Test split_dicts creates multiple files from large dictionary."""
        test_data = {str(i): f"value_{i}" for i in range(15)}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(test_data, temp_file)
            temp_filename = temp_file.name

        try:
            # Split with nsub=5 should create 3 files
            utils.split_dicts(temp_filename, nsub=5)

            base_name = temp_filename.split(".")[0]

            # Check that split files exist
            for i in range(1, 4):  # Should create 3 files
                split_file = f"{base_name}_{i}.json"
                assert os.path.exists(split_file)

                # Load and check content
                with open(split_file) as f:
                    data = json.load(f)
                    if i < 3:  # First two files should have 5 items each
                        assert len(data) == 5
                    else:  # Last file should have remaining items
                        assert len(data) == 5

                # Cleanup
                os.unlink(split_file)

        finally:
            # Cleanup original file
            os.unlink(temp_filename)

    @patch("oyente.utils.os.stat")
    @patch("oyente.utils.mmap.mmap")
    @patch("builtins.open")
    @patch("oyente.utils.re.findall")
    def test_run_re_file(self, mock_findall, mock_file, mock_mmap, mock_stat):
        """Test run_re_file performs regex search on file."""
        # Mock file size
        mock_stat.return_value.st_size = 1000

        # Mock file open context manager
        mock_file_obj = Mock()
        mock_file.return_value.__enter__ = Mock(return_value=mock_file_obj)
        mock_file.return_value.__exit__ = Mock(return_value=None)

        # Mock mmap
        mock_mmap_obj = Mock()
        mock_mmap.return_value = mock_mmap_obj

        # Mock regex results
        mock_findall.return_value = [b"match1", b"match2"]

        result = utils.run_re_file(r"test_pattern", "test_file.txt")

        assert result == [b"match1", b"match2"]
        mock_findall.assert_called_once_with(b"test_pattern", mock_mmap_obj)


@pytest.mark.integration
class TestSubprocessOperations:
    """Test subprocess operations with real command execution."""

    @patch("oyente.utils.subprocess.Popen")
    @patch("oyente.utils.shlex.split")
    def test_run_command_success(self, mock_split, mock_popen):
        """Test run_command executes command successfully."""
        mock_split.return_value = ["echo", "test"]

        mock_process = Mock()
        mock_process.communicate.return_value = (b"test output", b"")
        mock_popen.return_value = mock_process

        result = utils.run_command("echo test")

        assert result == "test output"
        mock_popen.assert_called_once()

    @patch("oyente.utils.subprocess.Popen")
    @patch("oyente.utils.shlex.split")
    def test_run_command_with_err(self, mock_split, mock_popen):
        """Test run_command_with_err returns both stdout and stderr."""
        mock_split.return_value = ["test", "command"]

        mock_process = Mock()
        mock_process.communicate.return_value = (b"output", b"error")
        mock_popen.return_value = mock_process

        out, err = utils.run_command_with_err("test command")

        assert out == "output"
        assert err == "error"


@pytest.mark.integration
@pytest.mark.slow
class TestContractInfoIntegration:
    """Test contract information gathering with external dependencies."""

    @patch("oyente.utils.run_re_file")
    def test_get_contract_info_success(self, mock_run_re_file):
        """Test get_contract_info successfully retrieves contract data."""
        # Mock successful regex results
        mock_run_re_file.side_effect = [[b"1,234 transactions"], [b"5.5 Ether"]]  # Transaction count  # Balance

        txs, value = utils.get_contract_info("0x123abc")

        assert txs == [b"1,234 transactions"]
        assert value == [b"5.5 Ether"]

    @patch("oyente.utils.run_re_file")
    @patch("oyente.utils.os.system")
    def test_get_contract_info_with_wget_fallback(self, mock_system, mock_run_re_file):
        """Test get_contract_info falls back to wget on first failure."""
        # First calls fail, then succeed
        mock_run_re_file.side_effect = [
            Exception("File not found"),  # First attempt fails
            [b"500 transactions"],  # After wget for txs
            [b"10.0 Ether"],  # After wget for balance
        ]

        txs, value = utils.get_contract_info("0x456def")

        # Should have called wget twice (for txs and balance)
        assert mock_system.call_count >= 2
        assert txs == [b"500 transactions"]
        assert value == [b"10.0 Ether"]

    @patch("oyente.utils.run_re_file")
    def test_get_contract_info_complete_failure(self, mock_run_re_file):
        """Test get_contract_info handles complete failure gracefully."""
        # All attempts fail
        mock_run_re_file.side_effect = Exception("Network error")

        txs, value = utils.get_contract_info("0x789ghi")

        # Should return "unknown" for both values
        assert txs == "unknown"
        assert value == "unknown"
