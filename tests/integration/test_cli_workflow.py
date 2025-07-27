"""Integration tests for CLI workflow functionality.

Tests the command-line interface including argument parsing,
help text, version display, and end-to-end workflow execution.
"""

import subprocess
import sys
from pathlib import Path

import pytest


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_help_option_displays_usage(self):
        """Test that --help option displays usage information."""
        result = subprocess.run(
            [sys.executable, "oyente/oyente.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()
        assert "oyente" in result.stdout.lower()

    def test_version_option_displays_version(self):
        """Test that --version option displays version information."""
        result = subprocess.run(
            [sys.executable, "oyente/oyente.py", "--version"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        # Version command may exit with 0 or 1 depending on implementation
        assert result.returncode in [0, 1]
        # Should contain some version-related text
        assert any(word in result.stdout.lower() for word in ["version", "oyente", "2.0"])

    def test_no_arguments_shows_help(self):
        """Test that running without arguments shows help or usage."""
        result = subprocess.run(
            [sys.executable, "oyente/oyente.py"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        # Should show usage information or error
        assert result.returncode != 0
        assert any(
            word in (result.stdout + result.stderr).lower() for word in ["usage", "help", "required", "arguments"]
        )


@pytest.mark.slow
class TestCLIWorkflow:
    """Test complete CLI workflow scenarios."""

    def test_invalid_file_path_returns_error(self):
        """Test that providing invalid file path returns appropriate error."""
        result = subprocess.run(
            [sys.executable, "oyente/oyente.py", "-s", "nonexistent.sol"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        assert result.returncode != 0
        assert any(
            word in (result.stdout + result.stderr).lower()
            for word in ["error", "not found", "file", "exist", "critical", "compilation", "failed"]
        )

    def test_invalid_option_returns_error(self):
        """Test that invalid command line options return error."""
        result = subprocess.run(
            [sys.executable, "oyente/oyente.py", "--invalid-option"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        assert result.returncode != 0
        assert any(
            word in (result.stdout + result.stderr).lower() for word in ["error", "unrecognized", "invalid", "unknown"]
        )
