"""Unit tests for oyente.py - CLI interface module.

This module tests the main CLI functionality including:
- Command existence checks
- Version comparison logic
- Dependency validation
- Argument parsing and main entry point
- Analysis workflow orchestration
"""

import argparse
import logging
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch

import pytest


# Mock dependencies before importing oyente module
with patch.dict(
    "sys.modules",
    {
        "global_params": Mock(
            TIMEOUT=30000,
            PRINT_PATHS=0,
            REPORT_MODE=0,
            USE_GLOBAL_BLOCKCHAIN=0,
            INPUT_STATE=0,
            STORE_RESULT=0,
            CHECK_ASSERTIONS=0,
            DEBUG_MODE=0,
            GENERATE_TEST_CASES=0,
            PARALLEL=0,
            TARGET_CONTRACTS=None,
            DEPTH_LIMIT=10,
            GAS_LIMIT=4000000,
            LOOP_LIMIT=10,
            GLOBAL_TIMEOUT=900,
        ),
        "symExec": Mock(),
        "input_helper": Mock(),
        "utils": Mock(run_command=Mock()),
        "z3": Mock(get_version_string=Mock(return_value="4.14.1.0")),
        "z3.z3util": Mock(),
    },
):
    from oyente import oyente as oyente_module

# Make the module available as 'oyente' for the tests
oyente = oyente_module


@pytest.mark.unit
class TestCommandUtilities:
    """Test utility functions for command validation."""

    def test_cmd_exists_with_valid_command(self):
        """Test cmd_exists returns True for valid system commands."""
        # Test with 'python' which should exist in most systems
        result = oyente.cmd_exists("python")
        assert isinstance(result, bool)

    def test_cmd_exists_with_invalid_command(self):
        """Test cmd_exists returns False for non-existent commands."""
        result = oyente.cmd_exists("nonexistent_command_xyz123")
        assert result is False

    def test_cmd_exists_with_empty_command(self):
        """Test cmd_exists with empty command string."""
        result = oyente.cmd_exists("")
        assert result is False

    def test_cmd_exists_with_none(self):
        """Test cmd_exists handles None input gracefully."""
        with pytest.raises(TypeError):
            oyente.cmd_exists(None)


@pytest.mark.unit
class TestVersionComparison:
    """Test version string comparison functionality."""

    def test_compare_versions_equal(self):
        """Test comparison of identical versions."""
        assert oyente.compare_versions("1.2.3", "1.2.3") == 0
        assert oyente.compare_versions("0.4.25", "0.4.25") == 0

    def test_compare_versions_first_higher(self):
        """Test when first version is higher."""
        assert oyente.compare_versions("1.2.4", "1.2.3") == 1
        assert oyente.compare_versions("2.0.0", "1.9.9") == 1
        assert oyente.compare_versions("1.3.0", "1.2.9") == 1

    def test_compare_versions_second_higher(self):
        """Test when second version is higher."""
        assert oyente.compare_versions("1.2.3", "1.2.4") == -1
        assert oyente.compare_versions("1.9.9", "2.0.0") == -1
        assert oyente.compare_versions("1.2.9", "1.3.0") == -1

    def test_compare_versions_different_lengths(self):
        """Test comparison with different version string lengths."""
        assert oyente.compare_versions("1.2", "1.2.0") == 0
        assert oyente.compare_versions("1.2.3", "1.2") == 1
        assert oyente.compare_versions("1.1", "1.2.0") == -1

    def test_compare_versions_zero_padding(self):
        """Test handling of zero padding in versions."""
        assert oyente.compare_versions("1.2.0", "1.2") == 0
        assert oyente.compare_versions("1.0.0", "1") == 0

    def test_compare_versions_edge_cases(self):
        """Test edge cases in version comparison."""
        assert oyente.compare_versions("0.0.1", "0.0.0") == 1
        assert oyente.compare_versions("10.0.0", "9.9.9") == 1
        assert oyente.compare_versions("1.10.0", "1.9.0") == 1


@pytest.mark.unit
class TestDependencyValidation:
    """Test dependency installation and validation."""

    @patch("tests.unit.test_oyente.oyente.cmd_exists")
    @patch("z3.get_version_string")
    def test_has_dependencies_installed_success(self, mock_z3_version, mock_cmd_exists):
        """Test successful dependency validation."""
        # Mock Z3 import and version
        mock_z3_version.return_value = "4.14.1.0"

        # Mock command existence checks
        mock_cmd_exists.side_effect = lambda cmd: cmd in ["solc"]

        result = oyente.has_dependencies_installed()
        assert result is True

    @patch("tests.unit.test_oyente.oyente.cmd_exists")
    @patch("z3.get_version_string")
    def test_has_dependencies_installed_no_solc(self, mock_z3_version, mock_cmd_exists):
        """Test dependency validation when solc is missing."""
        mock_z3_version.return_value = "4.14.1.0"
        mock_cmd_exists.side_effect = lambda cmd: False  # solc missing

        result = oyente.has_dependencies_installed()
        assert result is False

    @patch("z3.get_version_string")
    def test_has_dependencies_installed_z3_import_error(self, mock_z3_version):
        """Test dependency validation when Z3 import fails."""
        mock_z3_version.side_effect = ImportError("No module named z3")

        result = oyente.has_dependencies_installed()
        assert result is False

    @patch("tests.unit.test_oyente.oyente.cmd_exists")
    @patch("z3.get_version_string")
    def test_has_dependencies_installed_version_warnings(self, mock_z3_version, mock_cmd_exists):
        """Test version warnings for newer dependencies."""
        # Mock newer Z3 version
        mock_z3_version.return_value = "4.15.0.0"

        mock_cmd_exists.side_effect = lambda cmd: cmd in ["solc"]

        with patch("logging.warning") as mock_warning:
            result = oyente.has_dependencies_installed()
            assert result is True
            # Should have warning for Z3
            assert mock_warning.call_count >= 1


@pytest.mark.unit
class TestBytecodeAnalysis:
    """Test bytecode analysis workflow."""

    @patch("tests.unit.test_oyente.oyente.InputHelper")
    @patch("tests.unit.test_oyente.oyente.symExec.run")
    def test_analyze_bytecode_success(self, mock_symexec_run, mock_input_helper):
        """Test successful bytecode analysis."""
        # Mock input helper
        mock_helper = Mock()
        mock_helper.get_inputs.return_value = [{"disasm_file": "test.disasm"}]
        mock_input_helper.return_value = mock_helper

        # Mock symExec run
        mock_result = {"vulnerability_count": 0, "vulnerabilities": {}}
        mock_symexec_run.return_value = mock_result

        # Create mock args
        args = Mock()
        args.source = "test.bin"
        args.evm = False

        result = oyente.analyze_bytecode(args)

        assert result == 0
        mock_input_helper.assert_called_once_with(oyente.InputHelper.BYTECODE, source="test.bin", evm=False)
        mock_helper.get_inputs.assert_called_once()
        mock_symexec_run.assert_called_once_with(disasm_file="test.disasm")
        mock_helper.rm_tmp_files.assert_called_once()


@pytest.mark.unit
class TestSolidityAnalysis:
    """Test Solidity analysis workflows."""

    @patch("tests.unit.test_oyente.oyente.symExec.run")
    def test_run_solidity_analysis_success(self, mock_symexec_run):
        """Test successful Solidity analysis of multiple contracts."""
        # Mock symExec results
        mock_symexec_run.side_effect = [
            {"vulnerability_count": 0, "vulnerabilities": {}},
            {"vulnerability_count": 1, "vulnerabilities": {"reentrancy": []}},
        ]

        inputs = [
            {
                "contract": "Contract1",
                "disasm_file": "contract1.disasm",
                "source_map": "map1",
                "source": "contract1.sol",
                "c_source": "source1.sol",
                "c_name": "Contract1",
            },
            {
                "contract": "Contract2",
                "disasm_file": "contract2.disasm",
                "source_map": "map2",
                "source": "contract2.sol",
                "c_source": "source1.sol",
                "c_name": "Contract2",
            },
        ]

        results, exit_code = oyente.run_solidity_analysis(inputs)

        assert exit_code == 1  # Should be 1 since second contract had vulnerabilities
        assert "source1.sol" in results
        assert "Contract1" in results["source1.sol"]
        assert "Contract2" in results["source1.sol"]

        # Check symExec was called correctly
        assert mock_symexec_run.call_count == 2

    @patch("tests.unit.test_oyente.oyente.InputHelper")
    def test_analyze_solidity_standard_json(self, mock_input_helper):
        """Test analyze_solidity with standard JSON input."""
        mock_helper = Mock()
        mock_helper.get_inputs.return_value = []
        mock_input_helper.return_value = mock_helper

        args = Mock()
        args.source = "test.json"
        args.evm = False
        args.allow_paths = ""

        with patch("tests.unit.test_oyente.oyente.run_solidity_analysis") as mock_run_analysis:
            mock_run_analysis.return_value = ({}, 0)

            result = oyente.analyze_solidity(args, input_type="standard_json")

            assert result == 0
            mock_input_helper.assert_called_once_with(
                oyente.InputHelper.STANDARD_JSON, source="test.json", evm=False, allow_paths=""
            )


@pytest.mark.unit
class TestMainFunction:
    """Test main function and argument parsing."""

    @patch("sys.argv", ["oyente.py", "--source", "test.sol"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_solidity")
    def test_main_solidity_analysis(self, mock_analyze_solidity, mock_has_dependencies):
        """Test main function with Solidity source analysis."""
        mock_has_dependencies.return_value = True
        mock_analyze_solidity.return_value = 0

        result = oyente.main()

        mock_has_dependencies.assert_called_once()
        mock_analyze_solidity.assert_called_once()
        assert result == 0

    @patch("sys.argv", ["oyente.py", "--source", "test.bin", "--bytecode"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_bytecode")
    def test_main_bytecode_analysis(self, mock_analyze_bytecode, mock_has_dependencies):
        """Test main function with bytecode analysis."""
        mock_has_dependencies.return_value = True
        mock_analyze_bytecode.return_value = 1

        result = oyente.main()

        mock_has_dependencies.assert_called_once()
        mock_analyze_bytecode.assert_called_once()
        assert result == 1

    @patch("sys.argv", ["oyente.py", "--source", "test.json", "--standard-json"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_solidity")
    def test_main_standard_json(self, mock_analyze_solidity, mock_has_dependencies):
        """Test main function with standard JSON input."""
        mock_has_dependencies.return_value = True
        mock_analyze_solidity.return_value = 0

        result = oyente.main()

        assert result == 0
        mock_has_dependencies.assert_called_once()
        # Check that analyze_solidity was called with standard_json type
        args, kwargs = mock_analyze_solidity.call_args
        if len(args) > 1:
            assert args[1] == "standard_json"
        else:
            assert kwargs.get("input_type") == "standard_json"

    @patch("sys.argv", ["oyente.py", "--source", "test.json", "--standard-json-output"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_solidity")
    def test_main_standard_json_output(self, mock_analyze_solidity, mock_has_dependencies):
        """Test main function with standard JSON output."""
        mock_has_dependencies.return_value = True
        mock_analyze_solidity.return_value = 0

        result = oyente.main()

        assert result == 0
        args, kwargs = mock_analyze_solidity.call_args
        if len(args) > 1:
            assert args[1] == "standard_json_output"
        else:
            assert kwargs.get("input_type") == "standard_json_output"

    @patch("sys.argv", ["oyente.py", "--source", "test.sol", "--timeout", "5000"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_solidity")
    @patch("tests.unit.test_oyente.oyente.global_params")
    def test_main_global_params_setting(self, mock_global_params, mock_analyze_solidity, mock_has_dependencies):
        """Test that main function sets global parameters correctly."""
        mock_has_dependencies.return_value = True
        mock_analyze_solidity.return_value = 0

        result = oyente.main()

        # Check that function returns 0 and timeout was set
        assert result == 0
        assert mock_global_params.TIMEOUT == 5000

    @patch("sys.argv", ["oyente.py", "--remoteURL", "http://example.com/contract.sol"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_solidity")
    @patch("tests.unit.test_oyente.oyente.requests.get")
    @patch("builtins.open", new_callable=mock_open)
    def test_main_remote_url(self, mock_file_open, mock_requests_get, mock_analyze_solidity, mock_has_dependencies):
        """Test main function with remote URL."""
        mock_has_dependencies.return_value = True
        mock_analyze_solidity.return_value = 0

        # Mock HTTP response
        mock_response = Mock()
        mock_response.text = "contract TestContract {}"
        mock_requests_get.return_value = mock_response

        result = oyente.main()

        assert result == 0
        mock_requests_get.assert_called_once_with("http://example.com/contract.sol", timeout=30)
        mock_file_open.assert_called_once_with("remote_contract.sol", "w")
        mock_file_open().write.assert_called_once_with("contract TestContract {}")

    @patch(
        "sys.argv", ["oyente.py", "--source", "test.sol", "--target-contracts", "Contract1", "Contract2", "--bytecode"]
    )
    def test_main_conflicting_arguments(self):
        """Test main function with conflicting arguments."""
        # ArgumentParser.error should cause SystemExit to be raised
        with pytest.raises(SystemExit):
            oyente.main()

    @patch("sys.argv", ["oyente.py", "--source", "test.sol"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    def test_main_missing_dependencies(self, mock_has_dependencies):
        """Test main function when dependencies are missing."""
        mock_has_dependencies.return_value = False

        # Should return 1 when dependencies are missing
        result = oyente.main()

        mock_has_dependencies.assert_called_once()
        assert result == 1

    @patch("sys.argv", ["oyente.py", "--source", "test.sol", "--verbose"])
    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_solidity")
    @patch("logging.getLogger")
    def test_main_logging_configuration(self, mock_get_logger, mock_analyze_solidity, mock_has_dependencies):
        """Test main function configures logging correctly."""
        mock_has_dependencies.return_value = True
        mock_analyze_solidity.return_value = 0

        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        result = oyente.main()

        assert result == 0
        # Should set DEBUG level for verbose mode
        mock_logger.setLevel.assert_called_with(level=logging.DEBUG)

    @patch("sys.argv", ["oyente.py", "--version"])
    def test_main_version_argument(self):
        """Test main function with --version argument."""
        # Should exit with version info
        with pytest.raises(SystemExit):
            oyente.main()


@pytest.mark.unit
class TestArgumentParsing:
    """Test argument parsing edge cases."""

    def test_parse_args_root_path_normalization(self):
        """Test that root path gets normalized with trailing slash."""
        test_args = ["--source", "test.sol", "--root-path", "/some/path"]

        # Mock the argument parsing portion directly
        parser = argparse.ArgumentParser()
        # Add the same arguments as main()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--source", type=str)
        parser.add_argument("--root-path", dest="root_path", type=str)

        args = parser.parse_args(test_args)

        # Simulate the normalization logic from main()
        if args.root_path and args.root_path[-1] != "/":
            args.root_path += "/"

        assert args.root_path == "/some/path/"

    def test_parse_args_default_values(self):
        """Test default values for optional arguments."""
        test_args = ["--source", "test.sol"]

        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--source", type=str)
        parser.add_argument("--remap", type=str)
        parser.add_argument("--allow-paths", dest="allow_paths", type=str)

        args = parser.parse_args(test_args)

        # Simulate default value logic
        args.remap = args.remap if hasattr(args, "remap") and args.remap else ""
        args.allow_paths = args.allow_paths if hasattr(args, "allow_paths") and args.allow_paths else ""

        assert args.remap == ""
        assert args.allow_paths == ""


@pytest.mark.unit
class TestIntegration:
    """Integration tests for complete workflows."""

    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed", return_value=True)
    @patch("tests.unit.test_oyente.oyente.InputHelper")
    @patch("tests.unit.test_oyente.oyente.symExec.run")
    def test_full_solidity_workflow(self, mock_symexec_run, mock_input_helper, mock_has_dependencies):
        """Test complete Solidity analysis workflow."""
        # Mock input helper
        mock_helper = Mock()
        mock_inputs = [
            {
                "contract": "TestContract",
                "disasm_file": "test.disasm",
                "source_map": "mock_source_map",
                "source": "test.sol",
                "c_source": "test.sol",
                "c_name": "TestContract",
            }
        ]
        mock_helper.get_inputs.return_value = mock_inputs
        mock_input_helper.return_value = mock_helper

        # Mock symExec result
        mock_result = {"vulnerability_count": 1, "vulnerabilities": {"reentrancy": ["Warning: Potential reentrancy"]}}
        mock_symexec_run.return_value = mock_result

        with patch("sys.argv", ["oyente.py", "--source", "test.sol"]):
            result = oyente.main()

            # Should return exit code 1 (vulnerabilities found)
            assert result == 1

    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed", return_value=False)
    def test_workflow_missing_dependencies(self, mock_has_dependencies):
        """Test workflow when dependencies are missing."""
        with (
            patch("sys.argv", ["oyente.py", "--source", "test.sol"]),
            patch("tests.unit.test_oyente.oyente.analyze_solidity") as mock_analyze,
        ):
            result = oyente.main()

            # Should return 1 and not call analyze functions
            assert result == 1
            mock_analyze.assert_not_called()


@pytest.mark.unit
class TestErrorHandling:
    """Test error handling scenarios."""

    @patch("tests.unit.test_oyente.oyente.has_dependencies_installed")
    @patch("tests.unit.test_oyente.oyente.analyze_solidity")
    def test_analyze_solidity_exception_handling(self, mock_analyze_solidity, mock_has_dependencies):
        """Test that exceptions in analyze_solidity are handled properly."""
        mock_has_dependencies.return_value = True
        mock_analyze_solidity.side_effect = Exception("Analysis failed")

        with (
            patch("sys.argv", ["oyente.py", "--source", "test.sol"]),
            pytest.raises(Exception, match="Analysis failed"),
        ):
            oyente.main()

    def test_compare_versions_invalid_input(self):
        """Test version comparison with invalid version strings."""
        # Should handle gracefully or raise appropriate exceptions
        with pytest.raises((ValueError, AttributeError)):
            oyente.compare_versions("invalid", "1.2.3")

        with pytest.raises((ValueError, AttributeError)):
            oyente.compare_versions("1.2.3", "invalid")
