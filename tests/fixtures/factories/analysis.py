"""
Analysis factory for generating analysis result objects.

This module provides factory classes for creating analysis results
including gas usage, vulnerability detection, and execution traces.
"""

from __future__ import annotations

from typing import Any

import factory
from faker import Faker

fake = Faker()


class AnalysisFactory(factory.Factory):
    """Factory for generating analysis result objects."""

    class Meta:
        model = dict

    # Basic execution metrics
    gas = factory.Faker("random_int", min=21000, max=1000000)
    gas_mem = factory.Faker("random_int", min=0, max=100000)
    paths_explored = factory.Faker("random_int", min=1, max=50)
    execution_time = factory.Faker("random_int", min=100, max=30000)  # milliseconds

    # Vulnerability results (empty lists by default)
    reentrancy_bug = factory.LazyFunction(list)
    money_concurrency_bug = factory.LazyFunction(list)
    time_dependency_bug = factory.LazyFunction(list)
    assertion_failure = factory.LazyFunction(list)
    integer_overflow = factory.LazyFunction(list)
    integer_underflow = factory.LazyFunction(list)
    callstack_attack = factory.LazyFunction(list)
    parity_multisig_bug_2 = factory.LazyFunction(list)

    # Execution paths
    buggy_paths = factory.LazyFunction(list)
    normal_paths = factory.LazyFunction(list)

    # Money flow tracking
    money_flow = factory.LazyFunction(list)

    # Coverage information
    evm_code_coverage = factory.Faker("random_int", min=50, max=100)
    basic_blocks_covered = factory.LazyFunction(list)
    instructions_covered = factory.LazyFunction(list)

    @classmethod
    def safe_contract(cls, **kwargs: Any) -> dict[str, Any]:
        """Create analysis result for a safe contract (no vulnerabilities)."""
        defaults = {
            "reentrancy_bug": [],
            "money_concurrency_bug": [],
            "time_dependency_bug": [],
            "assertion_failure": [],
            "integer_overflow": [],
            "integer_underflow": [],
            "callstack_attack": [],
            "parity_multisig_bug_2": [],
            "buggy_paths": [],
            "normal_paths": [list(range(0, 100, 5))],  # Single normal path
            "money_flow": [],
            "gas": fake.random_int(min=21000, max=50000),  # Lower gas for simple contracts
            "evm_code_coverage": fake.random_int(min=80, max=100),
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def with_reentrancy(cls, pcs: list[int] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Create analysis result with reentrancy vulnerability."""
        if pcs is None:
            pcs = [100, 150, 200]  # Default program counters

        defaults = {
            "reentrancy_bug": pcs,
            "buggy_paths": [pcs],
            "normal_paths": [],
            "money_flow": [
                {
                    "from": "contract",
                    "to": "external",
                    "amount": "1000000000000000000",  # 1 ETH in wei
                    "pc": pcs[0] if pcs else 100,
                }
            ],
            "gas": fake.random_int(min=50000, max=200000),  # Higher gas for complex operations
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def with_integer_overflow(cls, pcs: list[int] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Create analysis result with integer overflow vulnerability."""
        if pcs is None:
            pcs = [50, 75]

        defaults = {
            "integer_overflow": pcs,
            "buggy_paths": [pcs],
            "normal_paths": [],
            "gas": fake.random_int(min=25000, max=100000),
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def with_integer_underflow(cls, pcs: list[int] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Create analysis result with integer underflow vulnerability."""
        if pcs is None:
            pcs = [60, 85]

        defaults = {
            "integer_underflow": pcs,
            "buggy_paths": [pcs],
            "normal_paths": [],
            "gas": fake.random_int(min=25000, max=100000),
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def with_timestamp_dependency(cls, pcs: list[int] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Create analysis result with timestamp dependency."""
        if pcs is None:
            pcs = [300, 350]

        defaults = {
            "time_dependency_bug": pcs,
            "buggy_paths": [pcs],
            "normal_paths": [],
            "gas": fake.random_int(min=30000, max=80000),
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def with_assertion_failure(cls, pcs: list[int] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Create analysis result with assertion failure."""
        if pcs is None:
            pcs = [120, 140]

        defaults = {
            "assertion_failure": pcs,
            "buggy_paths": [pcs],
            "normal_paths": [],
            "gas": fake.random_int(min=25000, max=75000),
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def with_multiple_vulnerabilities(cls, vulnerabilities: list[str], **kwargs: Any) -> dict[str, Any]:
        """Create analysis result with multiple vulnerabilities."""
        result = cls.safe_contract(**kwargs)

        base_pc = 100
        for i, vuln in enumerate(vulnerabilities):
            pcs = [base_pc + i * 50, base_pc + i * 50 + 25]

            if vuln == "reentrancy":
                result["reentrancy_bug"] = pcs
                result["money_flow"].append(
                    {
                        "from": "contract",
                        "to": "external",
                        "amount": str(fake.random_int(min=10**15, max=10**18)),
                        "pc": pcs[0],
                    }
                )
            elif vuln == "integer_overflow":
                result["integer_overflow"] = pcs
            elif vuln == "integer_underflow":
                result["integer_underflow"] = pcs
            elif vuln == "timestamp_dependency":
                result["time_dependency_bug"] = pcs
            elif vuln == "assertion_failure":
                result["assertion_failure"] = pcs
            elif vuln == "callstack_attack":
                result["callstack_attack"] = pcs

        # Update paths and gas for complex analysis
        all_pcs = []
        for vuln in vulnerabilities:
            pcs = [base_pc + vulnerabilities.index(vuln) * 50, base_pc + vulnerabilities.index(vuln) * 50 + 25]
            all_pcs.extend(pcs)

        result["buggy_paths"] = [all_pcs]
        result["normal_paths"] = []  # No normal paths when vulnerabilities exist
        result["gas"] = fake.random_int(min=100000, max=500000)  # Higher gas for complex contracts

        return result


class ExecutionTraceFactory(factory.Factory):
    """Factory for generating execution trace objects."""

    class Meta:
        model = dict

    # Basic trace information
    pc = factory.Faker("random_int", min=0, max=10000)
    opcode = factory.Iterator(["PUSH1", "POP", "ADD", "MUL", "SLOAD", "SSTORE", "CALL", "JUMP"])
    gas_cost = factory.Faker("random_int", min=1, max=100)
    stack_size = factory.Faker("random_int", min=0, max=1024)
    memory_size = factory.Faker("random_int", min=0, max=1024)

    # Stack and memory state
    stack = factory.LazyFunction(
        lambda: [fake.random_int(min=0, max=2**256) for _ in range(fake.random_int(min=0, max=10))]
    )
    memory = factory.LazyFunction(
        lambda: [fake.random_int(min=0, max=255) for _ in range(fake.random_int(min=0, max=100))]
    )

    # Storage operations
    storage_changes = factory.LazyFunction(dict)

    @classmethod
    def simple_execution(cls, opcodes: list[str] | None = None, **kwargs: Any) -> list[dict[str, Any]]:
        """Create a simple execution trace."""
        if opcodes is None:
            opcodes = ["PUSH1", "PUSH1", "ADD", "PUSH1", "SSTORE", "STOP"]

        trace = []
        pc = 0
        stack = []

        for opcode in opcodes:
            if opcode.startswith("PUSH"):
                stack.append(fake.random_int(min=1, max=1000))
            elif opcode in ["ADD", "MUL", "SUB"]:
                if len(stack) >= 2:
                    stack.pop()
                    stack.pop()
                    stack.append(fake.random_int(min=1, max=2000))
            elif opcode == "POP":
                if stack:
                    stack.pop()
            elif opcode in ["SLOAD", "SSTORE"] and stack:
                stack.pop()
                if opcode == "SLOAD":
                    stack.append(fake.random_int(min=0, max=1000))

            trace.append(
                {
                    "pc": pc,
                    "opcode": opcode,
                    "gas_cost": _get_gas_cost(opcode),
                    "stack_size": len(stack),
                    "stack": stack.copy(),
                    "memory_size": 0,
                    "memory": [],
                    "storage_changes": {},
                }
            )

            pc += 1 if not opcode.startswith("PUSH") else 2

        return trace

    @classmethod
    def with_external_call(cls, **kwargs: Any) -> list[dict[str, Any]]:
        """Create execution trace with external call."""
        opcodes = [
            "PUSH1",
            "PUSH1",
            "PUSH1",
            "PUSH1",  # Push call parameters
            "PUSH20",  # Push address
            "GAS",  # Push gas
            "CALL",  # External call
            "POP",  # Pop return value
            "STOP",
        ]
        return cls.simple_execution(opcodes, **kwargs)


def _get_gas_cost(opcode: str) -> int:
    """Get typical gas cost for an opcode."""
    gas_costs = {
        "STOP": 0,
        "ADD": 3,
        "MUL": 5,
        "SUB": 3,
        "DIV": 5,
        "PUSH1": 3,
        "PUSH2": 3,
        "PUSH20": 3,
        "POP": 2,
        "SLOAD": 2100,
        "SSTORE": 20000,
        "CALL": 700,
        "JUMP": 8,
        "JUMPI": 10,
        "MLOAD": 3,
        "MSTORE": 3,
        "GAS": 2,
    }
    return gas_costs.get(opcode, 3)  # Default to 3 gas
