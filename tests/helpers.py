"""Shared test utilities for oyente+ tests.

This module provides common helper functions and utilities used across
unit and integration tests to reduce code duplication.
"""

import json
import subprocess
import sys
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from typing import Optional
from typing import Union
from unittest.mock import Mock
from unittest.mock import patch


def run_oyente_cli(
    args: list[str],
    cwd: Optional[Path] = None,
    check: bool = False,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """Run oyente CLI with given arguments.

    Args:
        args: Command line arguments (without python/oyente.py prefix)
        cwd: Working directory for command execution
        check: Whether to raise exception on non-zero exit code
        timeout: Command timeout in seconds

    Returns:
        CompletedProcess instance with returncode, stdout, stderr

    Example:
        result = run_oyente_cli(["-s", "contract.sol", "--verbose"])
        assert result.returncode == 0
    """
    if cwd is None:
        # Default to project root (3 levels up from tests/helpers.py)
        cwd = Path(__file__).parent.parent

    cmd = [sys.executable, "oyente/oyente.py", *args]

    # Default timeout to prevent hanging tests
    if timeout is None:
        timeout = 30

    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        cwd=cwd,
        check=check,
        timeout=timeout,
    )


@contextmanager
def temp_solidity_file(content: str, filename: str = "test_contract.sol") -> Generator[Path, None, None]:
    """Create a temporary Solidity file with given content.

    Args:
        content: Solidity source code content
        filename: Name for the temporary file

    Yields:
        Path to the created temporary file

    Example:
        with temp_solidity_file(contract_code) as sol_file:
            result = compile_contract(sol_file)
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / filename
        file_path.write_text(content)
        yield file_path


@contextmanager
def temp_bytecode_file(bytecode: str, filename: str = "contract.bin") -> Generator[Path, None, None]:
    """Create a temporary bytecode file.

    Args:
        bytecode: EVM bytecode string (hex)
        filename: Name for the temporary file

    Yields:
        Path to the created temporary file
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / filename
        file_path.write_text(bytecode)
        yield file_path


@contextmanager
def temp_json_file(data: dict[str, Any], filename: str = "data.json") -> Generator[Path, None, None]:
    """Create a temporary JSON file with given data.

    Args:
        data: Dictionary to serialize as JSON
        filename: Name for the temporary file

    Yields:
        Path to the created temporary file
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / filename
        file_path.write_text(json.dumps(data, indent=2))
        yield file_path


def create_mock_compilation_result(
    contract_name: str = "TestContract",
    bytecode: str = "608060405234801561001057600080fd5b50",
    source_map: Optional[str] = None,
) -> dict[str, Any]:
    """Create a mock compilation result structure.

    Args:
        contract_name: Name of the contract
        bytecode: EVM bytecode for the contract
        source_map: Optional source map string

    Returns:
        Dictionary mimicking crytic-compile output structure
    """
    return {
        "contracts": {
            f"{contract_name}.sol": {
                contract_name: {
                    "evm": {
                        "bytecode": {
                            "object": bytecode,
                            "sourceMap": source_map or "",
                        }
                    }
                }
            }
        }
    }


def create_standard_json_input(contract_name: str, contract_code: str, version: str = "0.8.0") -> dict[str, Any]:
    """Create a standard JSON input structure for Solidity compilation.

    Args:
        contract_name: Name of the contract
        contract_code: Solidity source code
        version: Solidity version

    Returns:
        Standard JSON input dictionary
    """
    return {
        "language": "Solidity",
        "sources": {f"{contract_name}.sol": {"content": contract_code}},
        "settings": {"optimizer": {"enabled": True, "runs": 200}, "outputSelection": {"*": {"*": ["*"]}}},
    }


def compile_contract_mock(
    source_file: Union[str, Path],
    allow_paths: Optional[list[str]] = None,
    libraries: Optional[dict[str, str]] = None,
) -> Mock:
    """Create a mock crytic-compile result for testing.

    Args:
        source_file: Path to source file
        allow_paths: List of allowed import paths
        libraries: Library addresses for linking

    Returns:
        Mock CryticCompile instance
    """
    mock_compile = Mock()
    mock_compile.contracts = ["TestContract"]
    mock_compile.contracts_names = ["TestContract"]
    mock_compile.contracts_filenames = {"TestContract": str(source_file)}

    # Mock compilation units
    mock_unit = Mock()
    mock_unit.contracts_names = ["TestContract"]
    mock_unit.filename_of_contract = {"TestContract": str(source_file)}
    mock_unit.bytecode_runtime = lambda _: "608060405234801561001057600080fd5b50"
    mock_unit.srcmap_runtime = lambda _: "26:299:0:-:0;;;;;;;;;;;;;;"

    mock_compile.compilation_units = {"TestContract": mock_unit}

    return mock_compile


@contextmanager
def mock_crytic_compile_context(
    success: bool = True,
    contracts: Optional[list[str]] = None,
    bytecode: str = "608060405234801561001057600080fd5b50",
) -> Generator[Mock, None, None]:
    """Context manager for mocking crytic-compile.

    Args:
        success: Whether compilation should succeed
        contracts: List of contract names
        bytecode: Bytecode to return for contracts

    Yields:
        Mock CryticCompile class
    """
    with patch("crytic_compile.CryticCompile") as mock_class:
        if success:
            instance = compile_contract_mock("test.sol", allow_paths=None, libraries=None)
            if contracts:
                instance.contracts = contracts
                instance.contracts_names = contracts
            instance.compilation_units = {
                name: Mock(bytecode_runtime=lambda _: bytecode, srcmap_runtime=lambda _: "26:299:0:-:0;;;;;;;;;;;;;;")
                for name in (contracts or ["TestContract"])
            }
            mock_class.return_value = instance
        else:
            from tests.mocks.mock_crytic_compile import MockInvalidCompilationError

            mock_class.side_effect = MockInvalidCompilationError("Compilation failed")

        yield mock_class


def assert_vulnerability_found(output: str, vulnerability_type: str, count: Optional[int] = None) -> None:
    """Assert that a vulnerability was found in oyente output.

    Args:
        output: Oyente output string (stdout)
        vulnerability_type: Type of vulnerability to check
        count: Expected number of occurrences (if specified)

    Raises:
        AssertionError: If vulnerability not found or count mismatch
    """
    vuln_lower = vulnerability_type.lower()
    output_lower = output.lower()

    assert vuln_lower in output_lower, f"Expected '{vulnerability_type}' vulnerability not found in output"

    if count is not None:
        actual_count = output_lower.count(vuln_lower)
        assert actual_count == count, f"Expected {count} '{vulnerability_type}' vulnerabilities, found {actual_count}"


def assert_no_vulnerabilities(output: str) -> None:
    """Assert that no vulnerabilities were found in oyente output.

    Args:
        output: Oyente output string (stdout)

    Raises:
        AssertionError: If vulnerabilities were found
    """
    vulnerability_keywords = [
        "vulnerability",
        "vulnerabilities",
        "reentrancy",
        "integer overflow",
        "integer underflow",
        "callstack",
        "timestamp dependency",
        "assertion failure",
    ]

    output_lower = output.lower()
    found_vulns = [kw for kw in vulnerability_keywords if kw in output_lower]

    assert not found_vulns, f"Unexpected vulnerabilities found: {found_vulns}"


def create_test_bytecode(opcodes: list[str], with_metadata: bool = False) -> str:
    """Create test EVM bytecode from opcode list.

    Args:
        opcodes: List of EVM opcodes (e.g., ["PUSH1", "0x60", "PUSH1", "0x40"])
        with_metadata: Whether to append Solidity metadata

    Returns:
        Hex-encoded bytecode string

    Example:
        bytecode = create_test_bytecode(["PUSH1", "0x00", "DUP1", "REVERT"])
    """
    # Convert opcodes to their hex representations
    opcode_map = {
        "STOP": "00",
        "ADD": "01",
        "MUL": "02",
        "SUB": "03",
        "DIV": "04",
        "SDIV": "05",
        "MOD": "06",
        "SMOD": "07",
        "ADDMOD": "08",
        "MULMOD": "09",
        "EXP": "0a",
        "SIGNEXTEND": "0b",
        "LT": "10",
        "GT": "11",
        "SLT": "12",
        "SGT": "13",
        "EQ": "14",
        "ISZERO": "15",
        "AND": "16",
        "OR": "17",
        "XOR": "18",
        "NOT": "19",
        "BYTE": "1a",
        "SHL": "1b",
        "SHR": "1c",
        "SAR": "1d",
        "SHA3": "20",
        "ADDRESS": "30",
        "BALANCE": "31",
        "ORIGIN": "32",
        "CALLER": "33",
        "CALLVALUE": "34",
        "CALLDATALOAD": "35",
        "CALLDATASIZE": "36",
        "CALLDATACOPY": "37",
        "CODESIZE": "38",
        "CODECOPY": "39",
        "GASPRICE": "3a",
        "EXTCODESIZE": "3b",
        "EXTCODECOPY": "3c",
        "RETURNDATASIZE": "3d",
        "RETURNDATACOPY": "3e",
        "EXTCODEHASH": "3f",
        "BLOCKHASH": "40",
        "COINBASE": "41",
        "TIMESTAMP": "42",
        "NUMBER": "43",
        "DIFFICULTY": "44",
        "GASLIMIT": "45",
        "CHAINID": "46",
        "SELFBALANCE": "47",
        "BASEFEE": "48",
        "POP": "50",
        "MLOAD": "51",
        "MSTORE": "52",
        "MSTORE8": "53",
        "SLOAD": "54",
        "SSTORE": "55",
        "JUMP": "56",
        "JUMPI": "57",
        "PC": "58",
        "MSIZE": "59",
        "GAS": "5a",
        "JUMPDEST": "5b",
        "PUSH0": "5f",
        "PUSH1": "60",
        "PUSH2": "61",
        "PUSH3": "62",
        "PUSH4": "63",
        "DUP1": "80",
        "DUP2": "81",
        "SWAP1": "90",
        "LOG0": "a0",
        "CREATE": "f0",
        "CALL": "f1",
        "RETURN": "f3",
        "REVERT": "fd",
        "INVALID": "fe",
        "SELFDESTRUCT": "ff",
    }

    bytecode_parts = []
    for opcode in opcodes:
        if opcode.startswith("0x"):
            # Raw hex value
            bytecode_parts.append(opcode[2:])
        elif opcode.upper() in opcode_map:
            # Known opcode
            bytecode_parts.append(opcode_map[opcode.upper()])
        else:
            # Assume it's already hex
            bytecode_parts.append(opcode)

    bytecode = "".join(bytecode_parts)

    if with_metadata:
        # Add minimal Solidity metadata
        metadata = "a264697066735822122000000000000000000000000000000000000000000000000000000000000000000064736f6c63430008000033"
        bytecode += metadata

    return bytecode
