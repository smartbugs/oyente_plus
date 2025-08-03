"""
Pytest configuration and shared fixtures for Oyente+ test suite.

This module provides the core testing infrastructure including:
- Common fixtures for file operations
- Mock objects for external dependencies
- Test data generators
- Utility functions for testing
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from io import StringIO
from pathlib import Path
from typing import Any
from typing import Generator
from unittest.mock import Mock
from unittest.mock import patch

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_z3_solver():
    """Mock Z3 solver for fast unit tests."""
    with patch("z3.Solver") as mock_solver_class:
        mock_instance = Mock()
        mock_instance.check.return_value = "sat"  # Default to satisfiable
        mock_instance.model.return_value = Mock()
        mock_instance.push = Mock()
        mock_instance.pop = Mock()
        mock_instance.add = Mock()
        mock_instance.assertions.return_value = []
        mock_solver_class.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_z3_unsat_solver():
    """Mock Z3 solver that always returns unsat."""
    with patch("z3.Solver") as mock_solver_class:
        mock_instance = Mock()
        mock_instance.check.return_value = "unsat"
        mock_solver_class.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def sample_contract_source() -> str:
    """Sample Solidity contract for testing."""
    return """
    pragma solidity ^0.8.0;
    contract SimpleToken {
        mapping(address => uint256) balances;

        function transfer(address to, uint256 amount) public {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
    """


@pytest.fixture
def sample_vulnerable_contract() -> str:
    """Sample vulnerable Solidity contract with reentrancy bug."""
    return """
    pragma solidity ^0.8.0;
    contract Vulnerable {
        mapping(address => uint256) balances;

        function withdraw() public {
            uint256 amount = balances[msg.sender];
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] = 0;  // State change after external call
        }
    }
    """


@pytest.fixture
def sample_bytecode() -> str:
    """Sample contract bytecode for testing."""
    # Simple bytecode: PUSH1 0x01, PUSH1 0x02, ADD, STOP
    return "6001600201600"


@pytest.fixture
def mock_subprocess():
    """Mock subprocess calls for external command execution."""
    with patch("subprocess.run") as mock_run:
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        yield mock_run


@pytest.fixture
def mock_global_params():
    """Mock global parameters for testing."""
    params = {
        "DEBUG": False,
        "PRINT_MODE": False,
        "UNIT_TEST": 0,
        "USE_GLOBAL_BLOCKCHAIN": False,
        "INPUT_STATE": False,
        "REPORT_MODE": False,
        "DATA_DIR": "",
        "CONTRACT_ADDRESS": "",
        "time_limit": 120,
        "depth_limit": 50,
        "loop_limit": 10,
        "z3_timeout": 30000,
    }
    with patch("oyente.global_params", params):
        yield params


@pytest.fixture
def analysis_result() -> dict[str, Any]:
    """Sample analysis result structure."""
    return {
        "gas": 0,
        "gas_mem": 0,
        "money_flow": [],
        "reentrancy_bug": [],
        "money_concurrency_bug": [],
        "time_dependency_bug": [],
        "assertion_failure": [],
        "integer_overflow": [],
        "integer_underflow": [],
        "callstack_attack": [],
        "parity_multisig_bug_2": [],
        "buggy_paths": [],
        "normal_paths": [],
    }


@pytest.fixture
def mock_source_map():
    """Mock source map for vulnerability testing."""
    mock_map = Mock()
    mock_map.get_source_code = Mock(return_value="contract code")
    mock_map.instr_positions = {100: 1, 200: 2, 300: 3}
    mock_map.mappings = []
    return mock_map


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset any global state between tests."""
    # This can be expanded to reset specific global variables
    # that might affect test isolation
    return


# Test markers for categorizing tests
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "property: marks tests as property-based tests")
    config.addinivalue_line("markers", "performance: marks tests as performance tests")
    config.addinivalue_line("markers", "requires_z3: marks tests that require Z3 solver")
    config.addinivalue_line("markers", "requires_solc: marks tests that require Solidity compiler")


# Pytest hooks for better test output
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on location."""
    for item in items:
        # Auto-mark tests based on their location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "property" in str(item.fspath):
            item.add_marker(pytest.mark.property)
        elif "performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)


# Utility fixtures for common test scenarios
@pytest.fixture
def mock_file_content():
    """Factory for creating mock file content."""

    def _create_content(content: str, path: Path | None = None) -> Mock:
        mock_open = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=content)))
        mock_open.return_value.__exit__ = Mock(return_value=None)
        return mock_open

    return _create_content


@pytest.fixture
def capture_logs():
    """Capture log output during tests."""
    log_capture = StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.DEBUG)

    # Get all loggers
    loggers = [logging.getLogger()]  # Root logger
    loggers.append(logging.getLogger("oyente"))

    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    yield log_capture

    # Cleanup
    for logger in loggers:
        logger.removeHandler(handler)


@pytest.fixture
def mock_crytic_compile():
    """Mock crytic-compile for contract compilation."""
    with patch("crytic_compile.CryticCompile") as mock_compile:
        mock_instance = Mock()
        mock_instance.bytecode_runtime = {"SimpleToken": "608060405234801561001057600080fd5b50"}
        mock_instance.bytecode_init = {"SimpleToken": "608060405234801561001057600080fd5b50"}
        mock_instance.contracts_names = ["SimpleToken"]
        mock_instance.compilation_units = {
            "SimpleToken.sol": Mock(source_unit_to_slither_file={"SimpleToken.sol": Mock()}),
        }
        mock_compile.return_value = mock_instance
        yield mock_instance
