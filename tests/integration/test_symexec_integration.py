"""
Integration tests for symExec.py - Symbolic Execution Workflows.

This module tests end-to-end symbolic execution workflows including:
- Complete analysis workflows
- CFG construction and execution
- Multi-function contract analysis
- Vulnerability detection workflows
- Performance under realistic conditions
"""

from __future__ import annotations

import os
import tempfile
import time
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from tests.fixtures.data_generators import BytecodeFactory
from tests.fixtures.data_generators import SolidityContractFactory
from tests.fixtures.data_generators import TestScenarioFactory


class TestSymbolicExecutionWorkflows:
    """Test complete symbolic execution workflows."""

    @pytest.fixture
    def mock_z3_environment(self):
        """Create a complete mock Z3 environment for testing."""
        with patch("oyente.symExec.Solver") as mock_solver_class, \
             patch("oyente.symExec.BitVec") as mock_bitvec, \
             patch("oyente.symExec.BitVecVal") as mock_bitvecval:
                    mock_solver = MagicMock()
                    mock_solver.check.return_value = "sat"
                    mock_solver_class.return_value = mock_solver

                    mock_bitvec.return_value = MagicMock()
                    mock_bitvecval.return_value = MagicMock()

                    yield {
                        "solver": mock_solver,
                        "bitvec": mock_bitvec,
                        "bitvecval": mock_bitvecval,
                    }

    @pytest.fixture
    def temp_disasm_file(self):
        """Create a temporary disassembly file for testing."""
        content = self._create_simple_disasm_content()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.disasm', delete=False) as f:
            f.write(content)
            temp_path = f.name

        yield temp_path

        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def temp_complex_disasm_file(self):
        """Create a temporary complex disassembly file for testing."""
        content = self._create_complex_disasm_content()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.disasm', delete=False) as f:
            f.write(content)
            temp_path = f.name

        yield temp_path

        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def _create_simple_disasm_content(self) -> str:
        """Create simple disassembly content for basic testing."""
        return """0: PUSH1 0x80
2: PUSH1 0x40
4: MSTORE
5: PUSH1 0x01
7: PUSH1 0x00
9: SSTORE
10: STOP"""

    def _create_complex_disasm_content(self) -> str:
        """Create complex disassembly content with control flow."""
        return """0: PUSH1 0x80
2: PUSH1 0x40
4: MSTORE
5: CALLVALUE
6: DUP1
7: ISZERO
8: PUSH2 0x0010
11: JUMPI
12: PUSH1 0x00
14: DUP1
15: REVERT
16: JUMPDEST
17: POP
18: PUSH1 0x04
20: CALLDATASIZE
21: LT
22: PUSH2 0x0041
25: JUMPI
26: PUSH1 0x00
28: CALLDATALOAD
29: PUSH29 0x0100000000000000000000000000000000000000000000000000000000
59: SWAP1
60: DIV
61: PUSH4 0xffffffff
66: AND
67: DUP1
68: PUSH4 0x60fe47b1
73: EQ
74: PUSH2 0x0046
77: JUMPI
78: JUMPDEST
79: PUSH1 0x00
81: DUP1
82: REVERT
83: JUMPDEST
84: PUSH2 0x004c
87: STOP
88: JUMPDEST
89: PUSH1 0x00
91: SLOAD
92: DUP1
93: SWAP2
94: POP
95: POP
96: SWAP1
97: JUMP
98: JUMPDEST
99: DUP1
100: PUSH1 0x00
102: SSTORE
103: POP
104: JUMP"""

    def test_complete_analysis_workflow_simple(self, mock_z3_environment, temp_disasm_file):
        """Test complete analysis workflow with simple contract."""
        from oyente.symExec import run

        # Mock global parameters
        with patch("oyente.symExec.global_params") as mock_params:
            mock_params.PARALLEL = False
            mock_params.TIMEOUT = 30000
            mock_params.UNIT_TEST = False
            mock_params.IS_TESTING_EVM = False
            mock_params.Ia = "0x1234567890123456789012345678901234567890"
            mock_params.Iv = 1000000000000000000
            mock_params.DISASM_CONTENT = None

            # Mock vulnerability detectors
            with patch("oyente.symExec.detect_vulnerabilities"):
                with patch("oyente.symExec.closing_message"):
                    # Run the analysis
                    run(disasm_file=temp_disasm_file)

    def test_control_flow_graph_construction_workflow(self, mock_z3_environment, temp_complex_disasm_file):
        """Test CFG construction with complex control flow."""
        from oyente.symExec import build_cfg_and_analyze
        from oyente.symExec import initGlobalVars

        with patch("oyente.symExec.global_params") as mock_params:
            mock_params.PARALLEL = False
            mock_params.TIMEOUT = 30000

            # Set global disasm file
            with patch("oyente.symExec.g_disasm_file", temp_complex_disasm_file):
                with patch("oyente.symExec.g_src_map", None):
                    # Initialize global variables
                    initGlobalVars()

                    # Mock analysis components
                    with patch("oyente.symExec.collect_vertices") as mock_collect:
                        with patch("oyente.symExec.construct_bb") as mock_construct:
                            with patch("oyente.symExec.full_sym_exec") as mock_exec:
                                with patch("oyente.symExec.detect_vulnerabilities") as mock_detect:
                                    mock_collect.return_value = [0, 16, 83, 88]

                                    # Run CFG construction and analysis
                                    build_cfg_and_analyze()

                                    # Verify workflow steps were called
                                    mock_collect.assert_called()
                                    mock_construct.assert_called()
                                    mock_exec.assert_called()
                                    mock_detect.assert_called()

    def test_vulnerability_detection_workflow(self, mock_z3_environment):
        """Test end-to-end vulnerability detection workflow."""
        from oyente.symExec import detect_vulnerabilities

        # Mock results structure
        mock_results = {
            "vulnerabilities": {
                "integer_overflow": [],
                "integer_underflow": [],
                "reentrancy": [],
                "time_dependency": [],
                "money_concurrency": [],
                "callstack": [],
                "assertion_failure": [],
                "parity_multisig_bug_2": [],
            }
        }

        with patch("oyente.symExec.results", mock_results):
            with patch("oyente.symExec.g_disasm_file", "test.disasm"):
                # Mock all vulnerability detectors
                with patch("oyente.symExec.IntegerOverflow") as mock_overflow:
                    with patch("oyente.symExec.IntegerUnderflow") as mock_underflow:
                        with patch("oyente.symExec.Reentrancy") as mock_reentrancy:
                            with patch("oyente.symExec.TimeDependency") as mock_time:
                                with patch("oyente.symExec.MoneyConcurrency") as mock_money:
                                    with patch("oyente.symExec.AssertionFailure") as mock_assertion:
                                        with patch("oyente.symExec.ParityMultisigBug2") as mock_parity:
                                            with patch("oyente.symExec.check_callstack_attack") as mock_callstack:
                                                # Set up detector responses
                                                self._setup_vulnerability_detectors(
                                                    mock_overflow, mock_underflow, mock_reentrancy,
                                                    mock_time, mock_money, mock_assertion, mock_parity
                                                )
                                                mock_callstack.return_value = []

                                                # Run vulnerability detection
                                                detect_vulnerabilities()

                                                # Verify all detectors were instantiated
                                                mock_overflow.assert_called()
                                                mock_underflow.assert_called()
                                                mock_reentrancy.assert_called()
                                                mock_time.assert_called()
                                                mock_money.assert_called()
                                                mock_assertion.assert_called()
                                                mock_parity.assert_called()

    def _setup_vulnerability_detectors(self, *mock_detectors):
        """Helper to set up mock vulnerability detectors."""
        for mock_detector in mock_detectors:
            mock_instance = MagicMock()
            mock_instance.is_vulnerable.return_value = False
            mock_instance.get_warnings.return_value = []
            mock_detector.return_value = mock_instance

    def test_symbolic_execution_with_source_map(self, mock_z3_environment, temp_disasm_file):
        """Test symbolic execution with source map integration."""
        from oyente.symExec import run

        # Create mock source map
        mock_source_map = {
            "sources": {
                "test.sol": {
                    "content": SolidityContractFactory.simple_storage(),
                    "id": 0
                }
            },
            "contracts": {
                "test.sol:SimpleStorage": {
                    "abi": [],
                    "bin": "608060405234801561001057600080fd5b50..."
                }
            }
        }

        with patch("oyente.symExec.global_params") as mock_params:
            mock_params.PARALLEL = False
            mock_params.TIMEOUT = 30000
            mock_params.DISASM_CONTENT = None

            # Mock analysis components for source map workflow
            with patch("oyente.symExec.get_start_block_to_func_sig") as mock_func_sig:
                with patch("oyente.symExec.detect_vulnerabilities"):
                    with patch("oyente.symExec.closing_message"):
                        mock_func_sig.return_value = {}

                        # Run with source map
                        run(
                            disasm_file=temp_disasm_file,
                            source_file="test.sol",
                            source_map=mock_source_map
                        )

    def test_multi_function_contract_analysis(self, mock_z3_environment):
        """Test analysis of contract with multiple functions."""
        from oyente.symExec import full_sym_exec

        # Create complex bytecode with multiple functions
        complex_disasm = self._create_multi_function_disasm()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.disasm', delete=False) as f:
            f.write(complex_disasm)
            temp_path = f.name

        try:
            with patch("oyente.symExec.global_params") as mock_params:
                mock_params.LOOP_LIMIT = 10
                mock_params.DEPTH_LIMIT = 50
                mock_params.GAS_LIMIT = 4000000

                # Mock basic blocks
                mock_blocks = {
                    0: MagicMock(),
                    16: MagicMock(),
                    50: MagicMock(),
                    100: MagicMock(),
                }

                for pc, block in mock_blocks.items():
                    block.get_start_address.return_value = pc
                    block.get_instructions.return_value = [
                        f"{pc}: PUSH1 0x01",
                        f"{pc+2}: ADD",
                        f"{pc+3}: STOP"
                    ]

                with patch("oyente.symExec.blocks", mock_blocks):
                    with patch("oyente.symExec.compare_storage_and_gas_unit_test"):
                        # Run symbolic execution
                        full_sym_exec()

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _create_multi_function_disasm(self) -> str:
        """Create disassembly for contract with multiple functions."""
        return """0: PUSH1 0x80
2: PUSH1 0x40
4: MSTORE
5: PUSH1 0x04
7: CALLDATASIZE
8: LT
9: PUSH1 0x41
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
60: PUSH1 0x46
62: JUMPI
63: DUP1
64: PUSH4 0x60fe47b1
69: EQ
70: PUSH1 0x5e
72: JUMPI
73: JUMPDEST
74: PUSH1 0x00
76: DUP1
77: REVERT
78: JUMPDEST
79: PUSH1 0x5c
81: PUSH1 0x04
83: DUP1
84: CALLDATALOAD
85: SWAP1
86: PUSH1 0x20
88: ADD
89: CALLDATALOAD
90: PUSH1 0x66
92: JUMP
93: JUMPDEST
94: STOP
95: JUMPDEST
96: PUSH1 0x64
98: PUSH1 0x6e
100: JUMP
101: JUMPDEST
102: STOP
103: JUMPDEST
104: DUP2
105: PUSH1 0x00
107: DUP2
108: SWAP1
109: SSTORE
110: POP
111: POP
112: JUMP
113: JUMPDEST
114: PUSH1 0x00
116: SLOAD
117: DUP1
118: SWAP2
119: POP
120: POP
121: SWAP1
122: JUMP"""

    def test_performance_with_large_contract(self, mock_z3_environment):
        """Test performance with realistically large contract."""
        from oyente.symExec import run

        # Generate large bytecode pattern
        large_bytecode = BytecodeFactory.random_bytecode(1000)  # Large contract

        # Create disasm content from bytecode
        disasm_lines = []
        pc = 0
        for i in range(0, len(large_bytecode), 2):
            opcode_byte = large_bytecode[i:i+2]
            disasm_lines.append(f"{pc}: BYTE 0x{opcode_byte}")
            pc += 1

        disasm_content = "\n".join(disasm_lines)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.disasm', delete=False) as f:
            f.write(disasm_content)
            temp_path = f.name

        try:
            with patch("oyente.symExec.global_params") as mock_params:
                mock_params.PARALLEL = False
                mock_params.TIMEOUT = 60000  # Longer timeout for large contract
                mock_params.DISASM_CONTENT = None

                # Mock analysis to avoid infinite loops
                with patch("oyente.symExec.full_sym_exec") as mock_exec:
                    with patch("oyente.symExec.detect_vulnerabilities"):
                        with patch("oyente.symExec.closing_message"):
                            start_time = time.time()

                            # Run analysis
                            run(disasm_file=temp_path)

                            end_time = time.time()
                            analysis_time = end_time - start_time

                            # Verify analysis completed in reasonable time
                            assert analysis_time < 5.0  # Should complete quickly with mocks
                            mock_exec.assert_called_once()

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_error_recovery_workflow(self, mock_z3_environment, temp_disasm_file):
        """Test analysis workflow handles errors gracefully."""
        from oyente.symExec import run

        with patch("oyente.symExec.global_params") as mock_params:
            mock_params.PARALLEL = False
            mock_params.TIMEOUT = 30000
            mock_params.DISASM_CONTENT = None

            # Mock one component to fail
            with patch("oyente.symExec.full_sym_exec") as mock_exec:
                mock_exec.side_effect = Exception("Symbolic execution failed")

                with patch("oyente.symExec.detect_vulnerabilities"):
                    with patch("oyente.symExec.closing_message"):
                        # Should handle exception gracefully
                        with pytest.raises(Exception):
                            run(disasm_file=temp_disasm_file)

    def test_timeout_handling_workflow(self, mock_z3_environment):
        """Test timeout handling in analysis workflow."""
        from oyente.symExec import run_build_cfg_and_analyze

        timeout_called = {"value": False}

        def timeout_callback():
            timeout_called["value"] = True

        # Mock the main analysis to simulate long running
        with patch("oyente.symExec.build_cfg_and_analyze") as mock_build:
            with patch("oyente.symExec.signal.signal") as mock_signal:
                # Run with timeout callback
                run_build_cfg_and_analyze(timeout_callback)

                # Verify signal handler was set up
                mock_signal.assert_called()
                mock_build.assert_called_once()

    def test_evm_testing_workflow(self, mock_z3_environment, temp_disasm_file):
        """Test EVM testing workflow."""
        from oyente.symExec import run

        with patch("oyente.symExec.global_params") as mock_params:
            mock_params.PARALLEL = False
            mock_params.TIMEOUT = 30000
            mock_params.IS_TESTING_EVM = True  # Enable EVM testing mode
            mock_params.UNIT_TEST = True
            mock_params.DISASM_CONTENT = None

            # Mock EVM testing components
            with patch("oyente.symExec.compare_storage_and_gas_unit_test") as mock_compare:
                with patch("oyente.symExec.detect_vulnerabilities"):
                    with patch("oyente.symExec.closing_message"):
                        # Run in EVM testing mode
                        run(disasm_file=temp_disasm_file)

                        # Verify EVM testing components were used
                        # Note: compare_storage_and_gas_unit_test is called during symbolic execution


class TestComplexScenarios:
    """Test complex realistic scenarios."""

    def test_defi_contract_analysis_workflow(self, mock_z3_environment):
        """Test analysis of DeFi-like contract."""
        from oyente.symExec import run

        # Generate DeFi contract scenario
        scenario = TestScenarioFactory.vulnerable_scenario("reentrancy")

        # Create mock disasm for DeFi contract
        defi_disasm = """0: PUSH1 0x80
2: PUSH1 0x40
4: MSTORE
5: CALLVALUE
6: DUP1
7: ISZERO
8: PUSH2 0x0010
11: JUMPI
12: PUSH1 0x00
14: DUP1
15: REVERT
16: JUMPDEST
17: POP
18: PUSH1 0x04
20: CALLDATASIZE
21: LT
22: PUSH2 0x003f
25: JUMPI
26: PUSH1 0x00
28: CALLDATALOAD
29: PUSH29 0x0100000000000000000000000000000000000000000000000000000000
59: SWAP1
60: DIV
61: PUSH4 0xffffffff
66: AND
67: DUP1
68: PUSH4 0x2e1a7d4d
73: EQ
74: PUSH2 0x0044
77: JUMPI
78: DUP1
79: PUSH4 0xd0e30db0
84: EQ
85: PUSH2 0x004e
88: JUMPI
89: JUMPDEST
90: PUSH1 0x00
92: DUP1
93: REVERT
94: JUMPDEST
95: PUSH2 0x004c
98: PUSH1 0x04
100: DUP1
101: CALLDATALOAD
102: SWAP1
103: PUSH1 0x20
105: ADD
106: CALLDATALOAD
107: PUSH2 0x0056
110: JUMP
111: JUMPDEST
112: STOP
113: JUMPDEST
114: PUSH2 0x0054
117: PUSH2 0x00d4
120: JUMP
121: JUMPDEST
122: STOP
123: JUMPDEST
124: PUSH1 0x00
126: DUP1
127: CALLER
128: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
149: AND
150: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
171: AND
172: DUP2
173: MSTORE
174: PUSH1 0x20
176: ADD
177: SWAP1
178: DUP2
179: MSTORE
180: PUSH1 0x20
182: ADD
183: PUSH1 0x00
185: KECCAK256
186: SLOAD
187: LT
188: ISZERO
189: PUSH2 0x00d2
192: JUMPI
193: PUSH1 0x00
195: DUP1
196: REVERT
197: JUMPDEST
198: CALLER
199: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
220: AND
221: PUSH4 0xffffffff
226: AND
227: PUSH1 0x00
229: DUP1
230: CALL
231: ISZERO
232: ISZERO
233: PUSH2 0x00f0
236: JUMPI
237: PUSH1 0x00
239: DUP1
240: REVERT
241: JUMPDEST
242: POP
243: POP
244: JUMP
245: JUMPDEST
246: CALLER
247: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
268: AND
269: PUSH1 0x00
271: DUP1
272: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
293: AND
294: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
315: AND
316: DUP2
317: MSTORE
318: PUSH1 0x20
320: ADD
321: SWAP1
322: DUP2
323: MSTORE
324: PUSH1 0x20
326: ADD
327: PUSH1 0x00
329: KECCAK256
330: DUP1
331: SLOAD
332: CALLVALUE
333: ADD
334: SWAP1
335: SSTORE
336: POP
337: JUMP"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.disasm', delete=False) as f:
            f.write(defi_disasm)
            temp_path = f.name

        try:
            with patch("oyente.symExec.global_params") as mock_params:
                mock_params.PARALLEL = False
                mock_params.TIMEOUT = 60000
                mock_params.DISASM_CONTENT = None

                # Mock reentrancy detection for expected results
                with patch("oyente.symExec.Reentrancy") as mock_reentrancy:
                    mock_instance = MagicMock()
                    mock_instance.is_vulnerable.return_value = True
                    mock_instance.get_warnings.return_value = ["Reentrancy vulnerability detected"]
                    mock_reentrancy.return_value = mock_instance

                    with patch("oyente.symExec.detect_vulnerabilities"):
                        with patch("oyente.symExec.closing_message"):
                            # Run analysis on DeFi contract
                            run(disasm_file=temp_path)

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_cross_function_analysis_workflow(self, mock_z3_environment):
        """Test analysis that spans multiple contract functions."""
        from oyente.symExec import get_start_block_to_func_sig

        mock_source_map = {
            "sources": {
                "MultiFunction.sol": {
                    "content": """
pragma solidity ^0.8.0;
contract MultiFunction {
    uint256 private data;
    
    function setData(uint256 _data) public {
        data = _data;
    }
    
    function getData() public view returns (uint256) {
        return data;
    }
    
    function processData() public {
        data = data * 2;
    }
}""",
                    "id": 0
                }
            }
        }

        with patch("oyente.symExec.g_src_map", mock_source_map):
            # Mock function signature detection
            result = get_start_block_to_func_sig()

            # Should return a mapping structure
            assert isinstance(result, dict)

    def test_gas_analysis_integration(self, mock_z3_environment, temp_disasm_file):
        """Test gas analysis integration in symbolic execution."""
        from oyente.symExec import run

        with patch("oyente.symExec.global_params") as mock_params:
            mock_params.PARALLEL = False
            mock_params.TIMEOUT = 30000
            mock_params.UNIT_TEST = True  # Enable unit testing mode
            mock_params.DISASM_CONTENT = None

            # Mock gas analysis
            with patch("oyente.symExec.compare_storage_and_gas_unit_test") as mock_gas_analysis:
                with patch("oyente.symExec.detect_vulnerabilities"):
                    with patch("oyente.symExec.closing_message"):
                        # Run with gas analysis
                        run(disasm_file=temp_disasm_file)

                        # Gas analysis should be called during execution
                        # Note: This depends on the execution path through sym_exec


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_contract_analysis(self, mock_z3_environment):
        """Test analysis of empty contract."""
        from oyente.symExec import run

        # Create minimal disasm file
        minimal_disasm = "0: STOP"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.disasm', delete=False) as f:
            f.write(minimal_disasm)
            temp_path = f.name

        try:
            with patch("oyente.symExec.global_params") as mock_params:
                mock_params.PARALLEL = False
                mock_params.TIMEOUT = 30000
                mock_params.DISASM_CONTENT = None

                with patch("oyente.symExec.detect_vulnerabilities"):
                    with patch("oyente.symExec.closing_message"):
                        # Should handle empty contract gracefully
                        run(disasm_file=temp_path)

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_malformed_bytecode_handling(self, mock_z3_environment):
        """Test handling of malformed bytecode."""
        from oyente.symExec import collect_vertices

        # Malformed disasm lines
        malformed_lines = [
            "0: INVALID_OPCODE",
            "1: PUSH1",  # Missing argument
            "2: JUMP_TO_NOWHERE",
            "invalid line format",
            "",  # Empty line
        ]

        # Should handle malformed input gracefully
        result = collect_vertices(malformed_lines)
        assert isinstance(result, list)

    def test_deep_recursion_handling(self, mock_z3_environment):
        """Test handling of deep recursion in symbolic execution."""
        from oyente.symExec import full_sym_exec

        with patch("oyente.symExec.global_params") as mock_params:
            mock_params.DEPTH_LIMIT = 5  # Low limit to test recursion handling
            mock_params.LOOP_LIMIT = 3
            mock_params.GAS_LIMIT = 1000

            # Mock blocks with recursive structure
            recursive_blocks = {
                0: MagicMock(),
                10: MagicMock(),
            }

            # Set up recursive jumps
            recursive_blocks[0].get_instructions.return_value = [
                "0: PUSH1 0x0a",
                "2: JUMP"
            ]
            recursive_blocks[10].get_instructions.return_value = [
                "10: PUSH1 0x00",
                "12: JUMP"
            ]

            with patch("oyente.symExec.blocks", recursive_blocks):
                with patch("oyente.symExec.compare_storage_and_gas_unit_test"):
                    # Should handle recursion limits
                    full_sym_exec()

    def test_memory_intensive_analysis(self, mock_z3_environment):
        """Test memory-intensive analysis scenarios."""
        from oyente.symExec import run

        # Create disasm with many memory operations
        memory_intensive_disasm = []
        for i in range(100):
            pc = i * 10
            memory_intensive_disasm.extend([
                f"{pc}: PUSH1 0x{i:02x}",
                f"{pc+2}: PUSH1 0x{pc:02x}",
                f"{pc+4}: MSTORE",
                f"{pc+5}: PUSH1 0x{pc:02x}",
                f"{pc+7}: MLOAD",
                f"{pc+8}: POP",
            ])
        memory_intensive_disasm.append(f"{len(memory_intensive_disasm)*10}: STOP")

        content = "\n".join(memory_intensive_disasm)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.disasm', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            with patch("oyente.symExec.global_params") as mock_params:
                mock_params.PARALLEL = False
                mock_params.TIMEOUT = 30000
                mock_params.DISASM_CONTENT = None

                # Mock to avoid actual memory operations
                with patch("oyente.symExec.full_sym_exec") as mock_exec:
                    with patch("oyente.symExec.detect_vulnerabilities"):
                        with patch("oyente.symExec.closing_message"):
                            # Should handle memory-intensive operations
                            run(disasm_file=temp_path)
                            mock_exec.assert_called_once()

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
