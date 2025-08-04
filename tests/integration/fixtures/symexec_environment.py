"""
Complete symExec environment setup for integration testing.

This module provides fixtures and helpers to create a complete environment
for integration testing of the symExec module.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from tests.mocks.mock_symexec import MockAnalysisResult
from tests.mocks.mock_symexec import MockGlobalParams
from tests.mocks.mock_symexec import MockSourceMap
from tests.mocks.mock_symexec import MockSymbolicState
from tests.mocks.mock_symexec import create_mock_basic_blocks


@pytest.fixture
def symexec_test_environment():
    """Create a complete environment for symExec integration testing."""
    # Create temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Initialize global state
        global_state = {
            "g_disasm_file": str(temp_path / "test.disasm"),
            "g_src_map": None,
            "results": MockAnalysisResult(),
            "visited_pcs": set(),
            "solver": None,  # Will be mocked by Z3 patches
            "vertices": {},
            "edges": {},
            "blocks": {},
            "instructions": {},
            "callstack": [],
            "money_concurrency": [],
            "time_dependency": [],
            "reentrancy": [],
            "assertion_failure": [],
            "integer_overflow": [],
            "integer_underflow": [],
            "parity_multisig_bug_2": [],
        }

        # Mock global_params
        mock_params = MockGlobalParams()

        # Create basic blocks for testing
        basic_blocks = create_mock_basic_blocks([0, 16, 50, 100])

        # Create source map
        source_map = MockSourceMap()
        source_map.add_source("test.sol", "contract Test { }", 0)

        yield {
            "temp_dir": temp_path,
            "global_state": global_state,
            "global_params": mock_params,
            "basic_blocks": basic_blocks,
            "source_map": source_map,
        }


@pytest.fixture
def mock_vulnerability_detectors():
    """Create mock vulnerability detector classes."""
    detectors = {}

    # Define vulnerability types
    vuln_types = [
        "IntegerOverflow",
        "IntegerUnderflow",
        "Reentrancy",
        "TimeDependency",
        "MoneyConcurrency",
        "AssertionFailure",
        "ParityMultisigBug2",
    ]

    for vuln_type in vuln_types:
        mock_class = MagicMock()
        mock_instance = MagicMock()
        mock_instance.is_vulnerable.return_value = False
        mock_instance.get_warnings.return_value = []
        mock_class.return_value = mock_instance
        detectors[vuln_type] = (mock_class, mock_instance)

    return detectors


@pytest.fixture
def create_test_disasm_file():
    """Factory fixture to create test disassembly files."""
    created_files = []

    def _create_file(content: str, filename: str = "test.disasm") -> str:
        """Create a disassembly file with the given content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".disasm", delete=False, prefix=filename.replace(".disasm", "_")
        ) as f:
            f.write(content)
            created_files.append(f.name)
            return f.name

    yield _create_file

    # Cleanup
    import os

    for file_path in created_files:
        if os.path.exists(file_path):
            os.unlink(file_path)


@pytest.fixture
def patch_symexec_globals():
    """Patch all global variables in symExec module."""
    patches = []

    # Global variables to patch
    globals_to_patch = [
        "g_disasm_file",
        "g_src_map",
        "results",
        "visited_pcs",
        "solver",
        "vertices",
        "edges",
        "blocks",
        "instructions",
        "callstack",
        "money_concurrency",
        "time_dependency",
        "reentrancy",
        "assertion_failure",
        "integer_overflow",
        "integer_underflow",
        "parity_multisig_bug_2",
    ]

    def _patch():
        """Apply all patches."""
        for global_name in globals_to_patch:
            p = patch(f"oyente.symExec.{global_name}")
            patches.append(p)
            p.start()

        # Also patch functions that might fail
        func_patches = [
            patch("oyente.symExec.check_unit_test_file"),
            patch("oyente.symExec.check_sat"),
        ]

        for p in func_patches:
            patches.append(p)
            p.start()

    _patch()
    yield

    # Stop all patches
    for p in patches:
        p.stop()


def create_simple_contract_disasm() -> str:
    """Create simple contract disassembly for testing."""
    return """0: PUSH1 0x80
2: PUSH1 0x40
4: MSTORE
5: CALLVALUE
6: DUP1
7: ISZERO
8: PUSH1 0x10
10: JUMPI
11: PUSH1 0x00
13: DUP1
14: REVERT
15: JUMPDEST
16: POP
17: PUSH1 0x04
19: CALLDATASIZE
20: LT
21: PUSH1 0x3f
23: JUMPI
24: PUSH1 0x00
26: CALLDATALOAD
27: PUSH1 0x00
29: SSTORE
30: STOP"""


def create_vulnerable_contract_disasm(vuln_type: str) -> str:
    """Create contract disassembly with specific vulnerability pattern."""
    if vuln_type == "reentrancy":
        return """0: PUSH1 0x80
2: PUSH1 0x40
4: MSTORE
5: CALLER
6: PUSH1 0x00
8: DUP1
9: DUP1
10: DUP1
11: DUP6
12: PUSH1 0x00
14: DUP1
15: DUP1
16: DUP1
17: PUSH2 0x1000
20: GAS
21: CALL
22: ISZERO
23: PUSH1 0x30
25: JUMPI
26: CALLER
27: PUSH1 0x00
29: DUP2
30: SWAP1
31: SSTORE
32: STOP"""

    elif vuln_type == "integer_overflow":
        return """0: PUSH1 0xff
2: PUSH1 0xff
4: ADD
5: PUSH1 0x00
7: SSTORE
8: STOP"""

    elif vuln_type == "timestamp":
        return """0: TIMESTAMP
1: PUSH1 0x0a
3: MOD
4: PUSH1 0x05
6: LT
7: PUSH1 0x10
9: JUMPI
10: PUSH1 0x00
12: DUP1
13: REVERT
14: JUMPDEST
15: PUSH1 0x01
17: PUSH1 0x00
19: SSTORE
20: STOP"""

    elif vuln_type == "callstack":
        return """0: PUSH1 0x80
2: PUSH1 0x40
4: MSTORE
5: PUSH1 0x04
7: CALLDATASIZE
8: LT
9: PUSH1 0x3f
11: JUMPI
12: PUSH1 0x00
14: CALLDATALOAD
15: PUSH29 0x0100000000000000000000000000000000000000000000000000000000
45: SWAP1
46: DIV
47: PUSH4 0xffffffff
52: AND
53: DUP1
54: PUSH4 0x2e1a7d4d
59: EQ
60: PUSH2 0x44
63: JUMPI
64: JUMPDEST
65: PUSH1 0x00
67: DUP1
68: REVERT
69: JUMPDEST
70: PUSH1 0x42
72: PUSH1 0x00
74: PUSH1 0x00
76: PUSH1 0x00
78: PUSH1 0x00
80: CALLER
81: PUSH1 0xff
83: GAS
84: CALL
85: ISZERO
86: PUSH1 0x42
88: JUMPI
89: PUSH1 0x00
91: DUP1
92: REVERT
93: JUMPDEST
94: STOP"""

    else:
        return create_simple_contract_disasm()


def setup_mock_analysis_functions():
    """Set up common mock functions for analysis."""
    mocks = {}

    # Mock collect_vertices
    mock_collect = MagicMock()
    mock_collect.return_value = [0, 15, 23]  # Basic block start addresses
    mocks["collect_vertices"] = mock_collect

    # Mock construct_bb
    mock_construct = MagicMock()
    mocks["construct_bb"] = mock_construct

    # Mock full_sym_exec
    mock_exec = MagicMock()
    mocks["full_sym_exec"] = mock_exec

    # Mock detect_vulnerabilities
    mock_detect = MagicMock()
    mocks["detect_vulnerabilities"] = mock_detect

    # Mock get_init_state
    mock_init_state = MagicMock()
    mock_init_state.return_value = MockSymbolicState()
    mocks["get_init_state"] = mock_init_state

    return mocks
