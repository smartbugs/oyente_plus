"""Integration tests for compilation workflow.

Tests moved from test_input_helper.py that involve real compilation,
file I/O, and external tool dependencies.
"""

import json
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from tests.mocks.mock_crytic_compile import MockCryticCompile
from tests.mocks.mock_crytic_compile import MockInvalidCompilationError
from tests.mocks.mock_subprocess import MockSubprocessContext


# Mock the heavy dependencies for integration testing
with patch.dict(
    "sys.modules",
    {
        "global_params": Mock(WEB=False, DEBUG=False),
        "crytic_compile": Mock(CryticCompile=MockCryticCompile, InvalidCompilation=MockInvalidCompilationError),
        "ethutils.metadata": Mock(zeroMetadata=lambda bytecode: (bytecode, None)),
        "opcodes": Mock(INSTRUCTIONS={}),
        "source_map": Mock(SourceMap=Mock),
    },
):
    from oyente.input_helper import InputHelper


@pytest.mark.integration
class TestCompilationIntegration:
    """Test full compilation workflow with external dependencies."""

    def test_solidity_file_compilation_with_filesystem(self, temp_dir):
        """Test compilation of real Solidity file from filesystem."""
        from tests.helpers import mock_crytic_compile_context
        from tests.helpers import temp_solidity_file

        contract_code = """
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}
"""

        with temp_solidity_file(contract_code, "test_contract.sol") as sol_file, mock_crytic_compile_context(
            success=True, contracts=["TestContract"]
        ):
            helper = InputHelper(InputHelper.SOLIDITY, source=str(sol_file), evm=False, root_path=str(temp_dir))

            assert helper.source == str(sol_file)
            assert helper.input_type == InputHelper.SOLIDITY

    def test_standard_json_compilation_workflow(self, temp_dir):
        """Test standard JSON compilation workflow with file I/O."""
        from tests.helpers import create_mock_compilation_result
        from tests.helpers import create_standard_json_input
        from tests.helpers import temp_json_file

        # Create standard JSON input file
        contract_code = """
pragma solidity ^0.8.0;
contract SimpleToken {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""

        create_standard_json_input("SimpleToken", contract_code)

        # Create expected output
        output_content = create_mock_compilation_result("SimpleToken", "608060405234801561001057600080fd5b50")

        with temp_json_file(output_content, "output.json") as output_file, MockSubprocessContext(
            {"solc": {"returncode": 0, "stdout": json.dumps(output_content), "stderr": ""}}
        ), patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(output_content)

            helper = InputHelper(InputHelper.STANDARD_JSON_OUTPUT, source=str(output_file), evm=False)

            assert helper.source == str(output_file)
            assert helper.input_type == InputHelper.STANDARD_JSON_OUTPUT

    def test_bytecode_file_reading_integration(self, temp_dir):
        """Test reading bytecode from real file."""
        from tests.helpers import temp_bytecode_file

        bytecode_content = "608060405234801561001057600080fd5b50"

        with temp_bytecode_file(bytecode_content) as bytecode_file:
            helper = InputHelper(InputHelper.BYTECODE, source=str(bytecode_file), evm=False)

            assert helper.source == str(bytecode_file)
            assert helper.input_type == InputHelper.BYTECODE

    def test_large_bytecode_file_handling(self, temp_dir):
        """Test handling of large bytecode files."""
        from tests.helpers import temp_bytecode_file

        # Create a large bytecode file
        large_bytecode = "60" + "80" * 10000 + "fd"  # Large but valid bytecode

        with temp_bytecode_file(large_bytecode, "large_contract.bin") as bytecode_file:
            helper = InputHelper(InputHelper.BYTECODE, source=str(bytecode_file), evm=False)

            assert helper.source == str(bytecode_file)


@pytest.mark.integration
class TestCompilationErrorHandling:
    """Test compilation error handling with real scenarios."""

    def test_missing_file_error_handling(self):
        """Test handling of missing input files."""
        with pytest.raises(FileNotFoundError):
            helper = InputHelper(InputHelper.STANDARD_JSON_OUTPUT, source="nonexistent.json", evm=False)
            # File error occurs when trying to compile, not during initialization
            helper._get_compiled_contracts()

    def test_malformed_json_error_handling(self, temp_dir):
        """Test handling of malformed JSON files."""

        json_file = temp_dir / "malformed.json"
        json_file.write_text("{invalid json content")

        with pytest.raises(json.JSONDecodeError), open(json_file) as f:
            # This should raise a JSON decode error
            json.load(f)

    def test_invalid_bytecode_error_handling(self, temp_dir):
        """Test handling of invalid bytecode content."""
        invalid_file = temp_dir / "invalid.bin"
        invalid_file.write_text("invalid_bytecode_xyz")

        helper = InputHelper(InputHelper.BYTECODE, source=str(invalid_file), evm=False)

        # Should still create helper but may fail during analysis
        assert helper.source == str(invalid_file)

    def test_compilation_failure_with_crytic_compile(self, temp_dir):
        """Test handling of crytic-compile compilation failures."""
        # Create a malformed Solidity file that will cause compilation to fail
        invalid_sol_file = temp_dir / "invalid.sol"
        invalid_sol_file.write_text("contract { invalid syntax }")

        helper = InputHelper(
            InputHelper.SOLIDITY,
            source=str(invalid_sol_file),
            evm=False,
            root_path=str(temp_dir),
            compiled_contracts=[],
            compilation_err=False,
            remap="",
            allow_paths="",
        )

        # Mock the MockCryticCompile to raise an error when called
        with patch.object(
            MockCryticCompile, "__init__", side_effect=MockInvalidCompilationError("Syntax error")
        ), pytest.raises(MockInvalidCompilationError, match="Syntax error"):
            # This should handle the compilation error and raise the exception
            helper._compile_solidity()


@pytest.mark.integration
@pytest.mark.slow
class TestLibraryLinkingIntegration:
    """Test library linking functionality with external dependencies."""

    def test_library_detection_and_linking(self, temp_dir):
        """Test detection and linking of library dependencies."""
        from tests.mocks.mock_crytic_compile import get_contracts_with_libraries

        # Get test contracts with library dependencies
        contracts, libraries = get_contracts_with_libraries()

        mock_instance = MockCryticCompile(source="test.sol", contracts=contracts, libraries=libraries)

        with patch("crytic_compile.CryticCompile", return_value=mock_instance):
            helper = InputHelper(InputHelper.SOLIDITY, source="test.sol", evm=False)

            # Test library linking
            libs = {"Math": "0x123..."}
            result = helper._link_libraries("test.sol", libs)

            assert result is not None

    def test_complex_dependency_resolution(self, temp_dir):
        """Test resolution of complex library dependency chains."""
        # This would test more complex scenarios with multiple libraries
        # and dependency resolution
        pass


@pytest.mark.integration
class TestTemporaryFileManagement:
    """Test temporary file management in compilation workflow."""

    def test_temporary_file_creation_and_cleanup(self, temp_dir):
        """Test creation and cleanup of temporary compilation files."""
        helper = InputHelper(InputHelper.BYTECODE, source="contract.bin", evm=False)

        # Test temporary file path generation
        temp_files = helper._get_temporary_files("contract.bin")

        assert temp_files["disasm"] == "contract.bin.evm.disasm"
        assert temp_files["log"] == "contract.bin.evm.disasm.log"

    def test_temporary_file_collision_handling(self, temp_dir):
        """Test handling of temporary file name collisions."""
        # Create files that might collide with temporary files
        collision_file = temp_dir / "contract.bin.evm.disasm"
        collision_file.write_text("existing content")

        helper = InputHelper(InputHelper.BYTECODE, source=str(temp_dir / "contract.bin"), evm=False)

        # Should handle the collision gracefully
        temp_files = helper._get_temporary_files(str(temp_dir / "contract.bin"))
        assert temp_files is not None
