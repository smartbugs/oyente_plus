"""
Mock Z3 module for integration testing.

This module provides mock implementations of Z3 components to enable
integration testing of symExec without requiring actual Z3 solver.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock


class MockZ3Solver:
    """Mock implementation of Z3 Solver."""

    def __init__(self):
        self.assertions = []
        self.check_result = "sat"

    def add(self, assertion: Any) -> None:
        """Add assertion to solver."""
        self.assertions.append(assertion)

    def check(self) -> str:
        """Check satisfiability."""
        return self.check_result

    def model(self) -> dict[str, Any]:
        """Get model if satisfiable."""
        if self.check_result == "sat":
            return {"model": True}
        return {}

    def push(self) -> None:
        """Push solver context."""
        pass

    def pop(self) -> None:
        """Pop solver context."""
        pass

    def reset(self) -> None:
        """Reset solver state."""
        self.assertions = []

    def set(self, option: str, value: Any) -> None:
        """Set solver option."""
        pass


class MockBitVec:
    """Mock implementation of Z3 BitVec."""

    def __init__(self, name: str, size: int):
        self.name = name
        self.size = size
        self.value = MagicMock()

    def __repr__(self) -> str:
        return f"BitVec({self.name}, {self.size})"

    def __add__(self, other):
        return MockBitVec(f"({self.name} + {other})", self.size)

    def __sub__(self, other):
        return MockBitVec(f"({self.name} - {other})", self.size)

    def __mul__(self, other):
        return MockBitVec(f"({self.name} * {other})", self.size)

    def __div__(self, other):
        return MockBitVec(f"({self.name} / {other})", self.size)

    def __mod__(self, other):
        return MockBitVec(f"({self.name} % {other})", self.size)

    def __eq__(self, other):
        return MockBitVec(f"({self.name} == {other})", 1)

    def __ne__(self, other):
        return MockBitVec(f"({self.name} != {other})", 1)

    def __lt__(self, other):
        return MockBitVec(f"({self.name} < {other})", 1)

    def __le__(self, other):
        return MockBitVec(f"({self.name} <= {other})", 1)

    def __gt__(self, other):
        return MockBitVec(f"({self.name} > {other})", 1)

    def __ge__(self, other):
        return MockBitVec(f"({self.name} >= {other})", 1)

    def __and__(self, other):
        return MockBitVec(f"({self.name} & {other})", self.size)

    def __or__(self, other):
        return MockBitVec(f"({self.name} | {other})", self.size)

    def __xor__(self, other):
        return MockBitVec(f"({self.name} ^ {other})", self.size)

    def __lshift__(self, other):
        return MockBitVec(f"({self.name} << {other})", self.size)

    def __rshift__(self, other):
        return MockBitVec(f"({self.name} >> {other})", self.size)

    def __invert__(self):
        return MockBitVec(f"~{self.name}", self.size)


class MockBitVecVal:
    """Mock implementation of Z3 BitVecVal."""

    def __init__(self, value: int, size: int):
        self.value = value
        self.size = size

    def __repr__(self) -> str:
        return f"BitVecVal({self.value}, {self.size})"

    def as_long(self) -> int:
        """Get value as Python integer."""
        return self.value

    # Support arithmetic operations
    def __add__(self, other):
        if isinstance(other, MockBitVecVal):
            return MockBitVecVal(self.value + other.value, self.size)
        return MockBitVecVal(self.value + other, self.size)

    def __sub__(self, other):
        if isinstance(other, MockBitVecVal):
            return MockBitVecVal(self.value - other.value, self.size)
        return MockBitVecVal(self.value - other, self.size)

    def __mul__(self, other):
        if isinstance(other, MockBitVecVal):
            return MockBitVecVal(self.value * other.value, self.size)
        return MockBitVecVal(self.value * other, self.size)

    def __eq__(self, other):
        if isinstance(other, MockBitVecVal):
            return self.value == other.value
        return self.value == other


def Solver() -> MockZ3Solver:  # noqa: N802
    """Factory function for creating solver instances."""
    return MockZ3Solver()


def BitVec(name: str, size: int) -> MockBitVec:  # noqa: N802
    """Factory function for creating BitVec instances."""
    return MockBitVec(name, size)


def BitVecVal(value: int, size: int) -> MockBitVecVal:  # noqa: N802
    """Factory function for creating BitVecVal instances."""
    return MockBitVecVal(value, size)


# Additional Z3 functions that might be used
def simplify(expr: Any) -> Any:
    """Mock simplify function."""
    return expr


def is_true(expr: Any) -> bool:
    """Mock is_true function."""
    return bool(expr)


def is_false(expr: Any) -> bool:
    """Mock is_false function."""
    return not bool(expr)


def And(*args) -> Any:  # noqa: N802
    """Mock And function."""
    return MagicMock(args=args)


def Or(*args) -> Any:  # noqa: N802
    """Mock Or function."""
    return MagicMock(args=args)


def Not(arg: Any) -> Any:  # noqa: N802
    """Mock Not function."""
    return MagicMock(arg=arg)


def If(cond: Any, then_expr: Any, else_expr: Any) -> Any:  # noqa: N802
    """Mock If function."""
    return MagicMock(cond=cond, then_expr=then_expr, else_expr=else_expr)


def Extract(high: int, low: int, expr: Any) -> Any:  # noqa: N802
    """Mock Extract function."""
    return MagicMock(high=high, low=low, expr=expr)


def Concat(*args) -> Any:  # noqa: N802
    """Mock Concat function."""
    return MagicMock(args=args)


def UDiv(a: Any, b: Any) -> Any:  # noqa: N802
    """Mock unsigned division."""
    return MagicMock(a=a, b=b)


def URem(a: Any, b: Any) -> Any:  # noqa: N802
    """Mock unsigned remainder."""
    return MagicMock(a=a, b=b)


def ULT(a: Any, b: Any) -> Any:  # noqa: N802
    """Mock unsigned less than."""
    return MagicMock(a=a, b=b)


def ULE(a: Any, b: Any) -> Any:  # noqa: N802
    """Mock unsigned less than or equal."""
    return MagicMock(a=a, b=b)


def UGT(a: Any, b: Any) -> Any:  # noqa: N802
    """Mock unsigned greater than."""
    return MagicMock(a=a, b=b)


def UGE(a: Any, b: Any) -> Any:  # noqa: N802
    """Mock unsigned greater than or equal."""
    return MagicMock(a=a, b=b)


# Z3 constants that might be referenced
sat = "sat"
unsat = "unsat"
unknown = "unknown"


def create_integration_z3_environment() -> dict[str, Any]:
    """Create a complete Z3 environment for integration testing."""
    return {
        "Solver": Solver,
        "BitVec": BitVec,
        "BitVecVal": BitVecVal,
        "simplify": simplify,
        "is_true": is_true,
        "is_false": is_false,
        "And": And,
        "Or": Or,
        "Not": Not,
        "If": If,
        "Extract": Extract,
        "Concat": Concat,
        "UDiv": UDiv,
        "URem": URem,
        "ULT": ULT,
        "ULE": ULE,
        "UGT": UGT,
        "UGE": UGE,
        "sat": sat,
        "unsat": unsat,
        "unknown": unknown,
    }
