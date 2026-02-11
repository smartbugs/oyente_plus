"""
Mock implementations for symExec.py symbolic execution components.

This module provides mock implementations for symbolic execution components
to enable fast and isolated testing of symExec.py functionality.
"""

from __future__ import annotations

from typing import Any

# Dict and List imports removed - using built-in types


class MockBasicBlock:
    """Mock implementation of BasicBlock for testing."""

    def __init__(self, start_address: int, instructions: list[str] | None = None):
        self.start_address = start_address
        self.instructions = instructions or []
        self.end_address = start_address + len(self.instructions) - 1
        self.falls_to = None
        self.jump_target = None
        self.comes_from = []

    def get_start_address(self) -> int:
        """Get the starting address of the basic block."""
        return self.start_address

    def get_end_address(self) -> int:
        """Get the ending address of the basic block."""
        return self.end_address

    def get_instructions(self) -> list[str]:
        """Get the list of instructions in the basic block."""
        return self.instructions

    def set_falls_to(self, target: int) -> None:
        """Set the fall-through target."""
        self.falls_to = target

    def set_jump_target(self, target: int) -> None:
        """Set the jump target."""
        self.jump_target = target

    def add_comes_from(self, source: int) -> None:
        """Add a source block that can reach this block."""
        if source not in self.comes_from:
            self.comes_from.append(source)

    def get_falls_to(self) -> int | None:
        """Get the fall-through target."""
        return self.falls_to

    def get_jump_target(self) -> int | None:
        """Get the jump target."""
        return self.jump_target

    def get_comes_from(self) -> list[int]:
        """Get the list of source blocks."""
        return self.comes_from


class MockSymbolicState:
    """Mock implementation of symbolic execution state."""

    def __init__(self):
        self.stack: list[Any] = []
        self.memory: dict[int, Any] = {}
        self.storage: dict[Any, Any] = {}
        self.pc: int = 0
        self.gas: int = 1000000
        self.path_conditions: list[Any] = []
        self.variables: dict[str, Any] = {}

    def push(self, value: Any) -> None:
        """Push value onto stack."""
        self.stack.append(value)

    def pop(self) -> Any:
        """Pop value from stack."""
        if self.stack:
            return self.stack.pop()
        return 0  # Default value for empty stack

    def peek(self, index: int = 0) -> Any:
        """Peek at stack value without removing."""
        if index < len(self.stack):
            return self.stack[-(index + 1)]
        return 0

    def store_memory(self, offset: int, value: Any) -> None:
        """Store value in memory."""
        self.memory[offset] = value

    def load_memory(self, offset: int) -> Any:
        """Load value from memory."""
        return self.memory.get(offset, 0)

    def store_storage(self, key: Any, value: Any) -> None:
        """Store value in storage."""
        self.storage[key] = value

    def load_storage(self, key: Any) -> Any:
        """Load value from storage."""
        return self.storage.get(key, 0)

    def add_path_condition(self, condition: Any) -> None:
        """Add path condition."""
        self.path_conditions.append(condition)

    def copy(self) -> MockSymbolicState:
        """Create a copy of the state."""
        new_state = MockSymbolicState()
        new_state.stack = self.stack.copy()
        new_state.memory = self.memory.copy()
        new_state.storage = self.storage.copy()
        new_state.pc = self.pc
        new_state.gas = self.gas
        new_state.path_conditions = self.path_conditions.copy()
        new_state.variables = self.variables.copy()
        return new_state


class MockInstruction:
    """Mock implementation of EVM instruction."""

    def __init__(self, opcode: str, operand: str = "", pc: int = 0):
        self.opcode = opcode.upper()
        self.operand = operand
        self.pc = pc
        self.gas_cost = self._get_gas_cost()

    def _get_gas_cost(self) -> int:
        """Get gas cost for the instruction."""
        gas_costs = {
            "STOP": 0,
            "ADD": 3,
            "MUL": 5,
            "SUB": 3,
            "DIV": 5,
            "MOD": 5,
            "PUSH1": 3,
            "PUSH2": 3,
            "PUSH32": 3,
            "POP": 2,
            "MLOAD": 3,
            "MSTORE": 3,
            "SLOAD": 200,
            "SSTORE": 5000,
            "JUMP": 8,
            "JUMPI": 10,
            "CALL": 700,
            "RETURN": 0,
            "REVERT": 0,
            "SELFDESTRUCT": 5000,
        }
        base_opcode = self.opcode.split()[0]  # Remove any arguments
        return gas_costs.get(base_opcode, 3)  # Default gas cost

    def __str__(self) -> str:
        """String representation of instruction."""
        if self.operand:
            return f"{self.pc}: {self.opcode} {self.operand}"
        return f"{self.pc}: {self.opcode}"


class MockGlobalParams:
    """Mock implementation of global_params module."""

    def __init__(self):
        self.PARALLEL = False
        self.TIMEOUT = 30000
        self.UNIT_TEST = False
        self.IS_TESTING_EVM = False
        self.DEPTH_LIMIT = 50
        self.LOOP_LIMIT = 10
        self.GAS_LIMIT = 4000000
        self.Ia = "0x1234567890123456789012345678901234567890"
        self.Iv = 1000000000000000000  # 1 ETH in wei
        self.DISASM_CONTENT = None


class MockAnalysisResult:
    """Mock implementation of analysis result structure."""

    def __init__(self):
        self.vulnerabilities = {
            "integer_overflow": [],
            "integer_underflow": [],
            "reentrancy": [],
            "time_dependency": [],
            "money_concurrency": [],
            "callstack": [],
            "assertion_failure": [],
            "parity_multisig_bug_2": [],
        }
        self.evm_code_coverage = ""
        self.gas_usage = {"min": 21000, "max": 1000000}
        self.paths = {"normal": [], "buggy": []}

    def add_vulnerability(self, vuln_type: str, program_counters: list[int]) -> None:
        """Add vulnerability to results."""
        if vuln_type in self.vulnerabilities:
            self.vulnerabilities[vuln_type].extend(program_counters)

    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return any(vulns for vulns in self.vulnerabilities.values())


class MockVulnerabilityDetector:
    """Mock implementation of vulnerability detector base class."""

    def __init__(self, name: str, vulnerable: bool = False, warnings: list[str] | None = None):
        self.name = name
        self._vulnerable = vulnerable
        self._warnings = warnings or []

    def is_vulnerable(self) -> bool:
        """Check if vulnerability was detected."""
        return self._vulnerable

    def get_warnings(self) -> list[str]:
        """Get vulnerability warnings."""
        return self._warnings

    def set_vulnerable(self, vulnerable: bool, warnings: list[str] | None = None) -> None:
        """Set vulnerability status for testing."""
        self._vulnerable = vulnerable
        if warnings:
            self._warnings = warnings


class MockSourceMap:
    """Mock implementation of source map for testing."""

    def __init__(self):
        self.sources = {}
        self.contracts = {}
        self.pc_to_source = {}

    def add_source(self, filename: str, content: str, source_id: int = 0) -> None:
        """Add source file to the map."""
        self.sources[filename] = {
            "content": content,
            "id": source_id,
        }

    def add_contract(self, name: str, abi: list[Any] | None = None, bytecode: str = "") -> None:
        """Add contract to the map."""
        self.contracts[name] = {
            "abi": abi or [],
            "bin": bytecode,
        }

    def add_pc_mapping(self, pc: int, filename: str, line: int, column: int) -> None:
        """Add program counter to source mapping."""
        self.pc_to_source[pc] = {
            "filename": filename,
            "line": line,
            "column": column,
        }

    def get_source_location(self, pc: int) -> dict[str, Any] | None:
        """Get source location for program counter."""
        return self.pc_to_source.get(pc)


class MockDisassembler:
    """Mock implementation of disassembler for testing."""

    def __init__(self):
        self.instructions: list[MockInstruction] = []

    def add_instruction(self, opcode: str, operand: str = "", pc: int | None = None) -> None:
        """Add instruction to disassembly."""
        if pc is None:
            pc = len(self.instructions)
        instruction = MockInstruction(opcode, operand, pc)
        self.instructions.append(instruction)

    def get_disassembly(self) -> list[str]:
        """Get disassembly as list of strings."""
        return [str(instr) for instr in self.instructions]

    def create_simple_contract(self) -> list[str]:
        """Create simple contract disassembly."""
        return [
            "0: PUSH1 0x80",
            "2: PUSH1 0x40",
            "4: MSTORE",
            "5: CALLVALUE",
            "6: DUP1",
            "7: ISZERO",
            "8: PUSH1 0x10",
            "10: JUMPI",
            "11: PUSH1 0x00",
            "13: DUP1",
            "14: REVERT",
            "15: JUMPDEST",
            "16: POP",
            "17: STOP",
        ]

    def create_vulnerable_contract(self, vulnerability_type: str) -> list[str]:
        """Create contract with specific vulnerability pattern."""
        if vulnerability_type == "reentrancy":
            return [
                "0: PUSH1 0x80",
                "2: PUSH1 0x40",
                "4: MSTORE",
                "5: CALLER",
                "6: PUSH1 0x00",
                "8: DUP1",
                "9: CALL",  # External call
                "10: CALLER",
                "11: PUSH1 0x00",
                "13: DUP2",
                "14: SWAP1",
                "15: SSTORE",  # State change after call
                "16: STOP",
            ]
        elif vulnerability_type == "integer_overflow":
            return [
                "0: PUSH1 0xff",
                "2: PUSH1 0x01",
                "4: ADD",  # 255 + 1 = overflow
                "5: PUSH1 0x00",
                "7: SSTORE",
                "8: STOP",
            ]
        elif vulnerability_type == "timestamp_dependency":
            return [
                "0: TIMESTAMP",
                "1: PUSH1 0x0a",
                "3: MOD",
                "4: ISZERO",
                "5: PUSH1 0x10",
                "7: JUMPI",
                "8: CALLER",
                "9: SELFDESTRUCT",
                "10: JUMPDEST",
                "11: STOP",
            ]
        else:
            return self.create_simple_contract()


# Factory functions for creating mock objects
def create_mock_basic_blocks(addresses: list[int]) -> dict[int, MockBasicBlock]:
    """Create a set of mock basic blocks."""
    blocks = {}
    for i, addr in enumerate(addresses):
        instructions = [
            f"{addr}: PUSH1 0x{i:02x}",
            f"{addr+2}: POP",
        ]
        if i < len(addresses) - 1:
            instructions.append(f"{addr+3}: STOP")
        blocks[addr] = MockBasicBlock(addr, instructions)
    return blocks


def create_mock_analysis_environment():
    """Create a complete mock environment for analysis testing."""
    return {
        "global_params": MockGlobalParams(),
        "results": MockAnalysisResult(),
        "source_map": MockSourceMap(),
        "disassembler": MockDisassembler(),
        "blocks": create_mock_basic_blocks([0, 50, 100, 150]),
        "symbolic_state": MockSymbolicState(),
    }


def create_vulnerability_scenario(vuln_type: str) -> dict[str, Any]:
    """Create a complete vulnerability testing scenario."""
    disassembler = MockDisassembler()
    disasm_lines = disassembler.create_vulnerable_contract(vuln_type)

    # Create corresponding basic blocks
    blocks = {}
    for line in disasm_lines:
        if ":" in line:
            addr = int(line.split(":")[0])
            if addr not in blocks:
                blocks[addr] = MockBasicBlock(addr, [line])

    return {
        "vulnerability_type": vuln_type,
        "disasm_lines": disasm_lines,
        "basic_blocks": blocks,
        "expected_vulnerable": True,
    }


def create_performance_test_scenario(instruction_count: int = 1000) -> dict[str, Any]:
    """Create scenario for performance testing."""
    disassembler = MockDisassembler()

    # Create many instructions
    for i in range(instruction_count):
        pc = i * 3
        disassembler.add_instruction("PUSH1", f"0x{i % 256:02x}", pc)
        disassembler.add_instruction("POP", "", pc + 2)

    disassembler.add_instruction("STOP", "", instruction_count * 3)

    return {
        "instruction_count": instruction_count,
        "disasm_lines": disassembler.get_disassembly(),
        "expected_performance": {"max_time": 5.0, "max_memory": 100_000_000},  # 5 seconds, 100MB
    }
