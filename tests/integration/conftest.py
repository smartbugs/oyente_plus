"""Pytest configuration and fixtures for integration tests.

Provides shared fixtures and configuration for integration testing
including test data setup, temporary directories, and cleanup.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict
from unittest.mock import MagicMock

import pytest


# Add oyente to Python path for imports
oyente_path = os.path.join(os.path.dirname(__file__), "..", "..", "oyente")
if oyente_path not in sys.path:
    sys.path.insert(0, oyente_path)


@pytest.fixture(scope="session")
def integration_fixtures() -> Dict[str, Path]:
    """Provide paths to integration test fixtures.

    Returns:
        Dictionary with paths to different fixture directories:
        - contracts: Solidity contract test files
        - bytecode: EVM bytecode test files
        - expected: Expected analysis results
    """
    base_path = Path(__file__).parent / "fixtures"

    return {
        "contracts": base_path / "contracts",
        "bytecode": base_path / "bytecode",
        "expected": base_path / "expected",
    }


@pytest.fixture(scope="session", autouse=True)
def setup_integration_fixtures(integration_fixtures: Dict[str, Path]) -> None:
    """Set up integration test fixtures if they don't exist.

    Creates the fixture directory structure and basic test files
    for integration testing.
    """
    # Create fixture directories
    for fixture_path in integration_fixtures.values():
        fixture_path.mkdir(parents=True, exist_ok=True)

    contracts_dir = integration_fixtures["contracts"]
    bytecode_dir = integration_fixtures["bytecode"]
    expected_dir = integration_fixtures["expected"]

    # Create basic contract fixtures if they don't exist
    _create_contract_fixtures(contracts_dir)
    _create_bytecode_fixtures(bytecode_dir)
    _create_expected_results(expected_dir)


def _create_contract_fixtures(contracts_dir: Path) -> None:
    """Create basic Solidity contract fixtures for testing."""

    # Simple safe contract
    simple_safe = contracts_dir / "simple_safe.sol"
    if not simple_safe.exists():
        simple_safe.write_text(
            """
pragma solidity ^0.8.0;

contract SimpleSafe {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}
"""
        )

    # Reentrancy vulnerable contract
    reentrancy_vulnerable = contracts_dir / "reentrancy_vulnerable.sol"
    if not reentrancy_vulnerable.exists():
        reentrancy_vulnerable.write_text(
            """
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Vulnerable: external call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;  // State change after external call
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""
        )

    # Safe reentrancy pattern
    reentrancy_safe = contracts_dir / "reentrancy_safe.sol"
    if not reentrancy_safe.exists():
        reentrancy_safe.write_text(
            """
pragma solidity ^0.8.0;

contract ReentrancySafe {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier noReentrancy() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function withdraw() public noReentrancy {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        balances[msg.sender] = 0;  // State change before external call

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""
        )

    # Contract with syntax error for testing error handling
    syntax_error = contracts_dir / "syntax_error.sol"
    if not syntax_error.exists():
        syntax_error.write_text(
            """
pragma solidity ^0.8.0;

contract SyntaxError {
    uint256 public value
    // Missing semicolon above causes syntax error

    function setValue(uint256 _value) public {
        value = _value;
    }
}
"""
        )


def _create_bytecode_fixtures(bytecode_dir: Path) -> None:
    """Create basic bytecode fixtures for testing."""

    # Simple contract bytecode
    simple_contract = bytecode_dir / "simple_contract.bin"
    if not simple_contract.exists():
        # Basic contract bytecode that sets a storage variable
        simple_contract.write_text(
            "608060405234801561001057600080fd5b5060043610610047576000357c01000000000000000000000000000000000000000000000000000000009004806360fe47b11461004c5780636d4ce63c14610078575b600080fd5b6100766004803603602081101561006257600080fd5b8101908080359060200190929190505050610096565b005b6100806100a0565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea2646970667358221220"
        )

    # Malformed bytecode for error testing
    malformed = bytecode_dir / "malformed.bin"
    if not malformed.exists():
        malformed.write_text("invalid_bytecode_content_xyz")


def _create_expected_results(expected_dir: Path) -> None:
    """Create expected analysis results for testing."""

    # Expected result for safe contract
    safe_result = expected_dir / "reentrancy_safe.json"
    if not safe_result.exists():
        safe_result.write_text(
            json.dumps(
                {"vulnerabilities": {"reentrancy": []}, "analysis_time": 1.23, "contract_name": "ReentrancySafe"},
                indent=2,
            )
        )

    # Expected result for vulnerable contract
    vulnerable_result = expected_dir / "reentrancy_vulnerable.json"
    if not vulnerable_result.exists():
        vulnerable_result.write_text(
            json.dumps(
                {
                    "vulnerabilities": {
                        "reentrancy": [
                            {
                                "line": 8,
                                "column": 8,
                                "severity": "high",
                                "description": "Potential reentrancy vulnerability detected",
                                "recommendation": "Move state changes before external calls",
                            }
                        ]
                    },
                    "analysis_time": 2.45,
                    "contract_name": "ReentrancyVulnerable",
                },
                indent=2,
            )
        )


@pytest.fixture
def mock_z3_timeout():
    """Provide faster Z3 timeout for integration tests."""
    return 10000  # 10 seconds instead of default 30


@pytest.fixture
def mock_analysis_depth():
    """Provide limited analysis depth for faster integration tests."""
    return 10  # Shallow depth for faster execution


@pytest.fixture(scope="session", autouse=True)
def setup_mock_modules():
    """Mock required modules before any imports."""
    # Mock z3 first
    mock_z3 = MagicMock()

    # Add essential Z3 attributes
    mock_z3.Solver = MagicMock
    mock_z3.BitVec = MagicMock
    mock_z3.BitVecVal = MagicMock
    mock_z3.simplify = MagicMock()
    mock_z3.is_true = lambda x: True
    mock_z3.is_false = lambda x: False
    mock_z3.And = MagicMock()
    mock_z3.Or = MagicMock()
    mock_z3.Not = MagicMock()
    mock_z3.If = MagicMock()
    mock_z3.Extract = MagicMock()
    mock_z3.Concat = MagicMock()
    mock_z3.UDiv = MagicMock()
    mock_z3.URem = MagicMock()
    mock_z3.ULT = MagicMock()
    mock_z3.ULE = MagicMock()
    mock_z3.UGT = MagicMock()
    mock_z3.UGE = MagicMock()
    mock_z3.sat = "sat"
    mock_z3.unsat = "unsat"
    mock_z3.unknown = "unknown"

    # Mock other required modules for symExec
    mock_global_params = MagicMock()
    mock_global_params.PARALLEL = False
    mock_global_params.TIMEOUT = 30000
    mock_global_params.UNIT_TEST = False
    mock_global_params.IS_TESTING_EVM = False
    mock_global_params.DEPTH_LIMIT = 50
    mock_global_params.LOOP_LIMIT = 10
    mock_global_params.GAS_LIMIT = 4000000
    mock_global_params.Ia = "0x1234567890123456789012345678901234567890"
    mock_global_params.Iv = 1000000000000000000
    mock_global_params.DISASM_CONTENT = None

    # Mock other modules
    mock_analysis = MagicMock()
    mock_basicblock = MagicMock()
    mock_ethereum_data = MagicMock()
    mock_vargenerator = MagicMock()
    mock_vulnerability = MagicMock()
    mock_test_evm = MagicMock()
    mock_test_evm.global_test_params = MagicMock()
    mock_test_evm.global_test_params.EXCEPTION = Exception
    mock_test_evm.global_test_params.PICKLE_PATH = "/tmp"  # noqa: S108
    mock_test_evm.global_test_params.UNKNOWN_INSTRUCTION = "UNKNOWN"

    # Patch all modules in sys.modules
    modules_to_mock = {
        "z3": mock_z3,
        "global_params": mock_global_params,
        "analysis": mock_analysis,
        "basicblock": mock_basicblock,
        "ethereum_data": mock_ethereum_data,
        "vargenerator": mock_vargenerator,
        "vulnerability": mock_vulnerability,
        "test_evm": mock_test_evm,
        "test_evm.global_test_params": mock_test_evm.global_test_params,
        "six": MagicMock(),  # For Python 2/3 compatibility
    }

    original_modules = {}
    for module_name, mock_module in modules_to_mock.items():
        if module_name in sys.modules:
            original_modules[module_name] = sys.modules[module_name]
        sys.modules[module_name] = mock_module

    yield {
        "z3": mock_z3,
        "global_params": mock_global_params,
        "analysis": mock_analysis,
        "basicblock": mock_basicblock,
        "ethereum_data": mock_ethereum_data,
        "vargenerator": mock_vargenerator,
        "vulnerability": mock_vulnerability,
    }

    # Cleanup - restore original modules
    for module_name in modules_to_mock:
        if module_name in original_modules:
            sys.modules[module_name] = original_modules[module_name]
        else:
            if module_name in sys.modules:
                del sys.modules[module_name]


@pytest.fixture(autouse=True)
def integration_test_setup():
    """Set up environment for integration tests."""
    # Could set environment variables, configure logging, etc.
    yield
    # Cleanup after tests if needed
