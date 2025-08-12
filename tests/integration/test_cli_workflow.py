"""Integration tests for CLI workflow functionality.

Tests the command-line interface including argument parsing,
help text, version display, and end-to-end workflow execution.
"""

import pytest

from tests.helpers import run_oyente_cli


@pytest.mark.integration
class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_help_option_displays_usage(self):
        """Test that --help option displays usage information."""
        result = run_oyente_cli(["--help"])

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()
        assert "oyente" in result.stdout.lower()

    def test_version_option_displays_version(self):
        """Test that --version option displays version information."""
        result = run_oyente_cli(["--version"])

        # Version command may exit with 0 or 1 depending on implementation
        assert result.returncode in [0, 1]
        # Should contain some version-related text
        assert any(word in result.stdout.lower() for word in ["version", "oyente", "2.0"])

    def test_no_arguments_shows_help(self):
        """Test that running without arguments shows help or usage."""
        result = run_oyente_cli([])

        # Should show usage information or error
        assert result.returncode != 0
        assert any(
            word in (result.stdout + result.stderr).lower() for word in ["usage", "help", "required", "arguments"]
        )


@pytest.mark.slow
@pytest.mark.integration
class TestCLIWorkflow:
    """Test complete CLI workflow scenarios."""

    def test_invalid_file_path_returns_error(self):
        """Test that providing invalid file path returns appropriate error."""
        result = run_oyente_cli(["-s", "nonexistent.sol"])

        assert result.returncode != 0
        assert any(
            word in (result.stdout + result.stderr).lower()
            for word in ["error", "not found", "file", "exist", "critical", "compilation", "failed"]
        )

    def test_invalid_option_returns_error(self):
        """Test that invalid command line options return error."""
        result = run_oyente_cli(["--invalid-option"])

        assert result.returncode != 0
        assert any(
            word in (result.stdout + result.stderr).lower() for word in ["error", "unrecognized", "invalid", "unknown"]
        )
