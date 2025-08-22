"""
Mock Z3 solver infrastructure for fast unit testing.

This module provides mock implementations of Z3 solver components to enable
fast unit testing without requiring actual constraint solving. The mocks
support common Z3 operations while allowing tests to control solver behavior.
"""

from __future__ import annotations

from typing import Any
from typing import Literal
from typing import Union
from unittest.mock import MagicMock


class MockZ3Expr:
    """Mock Z3 expression for testing."""

    def __init__(self, name: str, value: Any = None):
        self.name = name
        self.value = value
        self._hash = hash(name)

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"MockZ3Expr({self.name})"

    def __eq__(self, other):
        if isinstance(other, MockZ3Expr):
            return self.name == other.name
        return False

    def __hash__(self):
        return self._hash

    def __add__(self, other):
        return MockZ3Expr(f"({self.name} + {other})")

    def __sub__(self, other):
        return MockZ3Expr(f"({self.name} - {other})")

    def __mul__(self, other):
        return MockZ3Expr(f"({self.name} * {other})")

    def __truediv__(self, other):
        return MockZ3Expr(f"({self.name} / {other})")

    def __lt__(self, other):
        return MockZ3Expr(f"({self.name} < {other})")

    def __le__(self, other):
        return MockZ3Expr(f"({self.name} <= {other})")

    def __gt__(self, other):
        return MockZ3Expr(f"({self.name} > {other})")

    def __ge__(self, other):
        return MockZ3Expr(f"({self.name} >= {other})")

    def __and__(self, other):
        return MockZ3Expr(f"({self.name} & {other})")

    def __or__(self, other):
        return MockZ3Expr(f"({self.name} | {other})")


class MockZ3BitVec(MockZ3Expr):
    """Mock Z3 BitVec for testing."""

    def __init__(self, name: str, size: int, value: Union[int, None] = None):
        super().__init__(name, value)
        self.size = size

    def size(self):
        return self.size


class MockZ3BitVecIntegration(MockZ3BitVec):
    """Mock Z3 BitVec with extended operations for integration testing."""

    def __xor__(self, other):
        return MockZ3BitVecIntegration(f"({self.name} ^ {other})", self.size)

    def __lshift__(self, other):
        return MockZ3BitVecIntegration(f"({self.name} << {other})", self.size)

    def __rshift__(self, other):
        return MockZ3BitVecIntegration(f"({self.name} >> {other})", self.size)

    def __invert__(self):
        return MockZ3BitVecIntegration(f"~{self.name}", self.size)

    def __div__(self, other):
        return MockZ3BitVecIntegration(f"({self.name} / {other})", self.size)

    def __mod__(self, other):
        return MockZ3BitVecIntegration(f"({self.name} % {other})", self.size)

    def as_long(self) -> int:
        """Get value as Python integer."""
        return self.value if self.value is not None else 0


class MockZ3Model:
    """Mock Z3 model for constraint solutions."""

    def __init__(self, values: Union[dict[str, Any], None] = None):
        self.values = values or {}

    def eval(self, expr: Union[MockZ3Expr, Any], model_completion: bool = True):
        """Evaluate expression in the model."""
        if isinstance(expr, MockZ3Expr):
            if expr.name in self.values:
                return self.values[expr.name]
            return expr.value if expr.value is not None else expr
        return expr

    def __getitem__(self, key):
        """Get value for a specific variable."""
        if isinstance(key, MockZ3Expr):
            return self.values.get(key.name, key)
        return self.values.get(str(key), key)

    def decls(self):
        """Return all declarations in the model."""
        return [MockZ3Expr(name) for name in self.values]


class MockZ3Solver:
    """Mock Z3 solver for fast unit testing."""

    def __init__(self, result: str = "sat", model_values: Union[dict[str, Any], None] = None):
        """
        Initialize mock solver.

        Args:
            result: The result to return from check() - "sat", "unsat", or "unknown"
            model_values: Values to return in the model when sat
        """
        self.result = result
        self.model_values = model_values or {}
        self.constraints: list[Any] = []
        self.assertions_list: list[Any] = []
        self.push_count = 0
        self.solver_stack: list[list[Any]] = []
        self.timeout_value: Union[int, None] = None
        self.set_params: dict[str, Any] = {}

    def add(self, *constraints):
        """Add constraints to the solver."""
        for constraint in constraints:
            self.constraints.append(constraint)
            self.assertions_list.append(constraint)

    def check(self, *assumptions):
        """Check satisfiability of constraints."""
        return self.result

    def model(self):
        """Get model for satisfiable constraints."""
        if self.result == "sat":
            return MockZ3Model(self.model_values)
        raise Exception("Model is not available (unsat or unknown)")

    def push(self):
        """Push solver state."""
        self.push_count += 1
        self.solver_stack.append(self.constraints.copy())

    def pop(self, num: int = 1):
        """Pop solver state."""
        for _ in range(min(num, len(self.solver_stack))):
            if self.solver_stack:
                self.constraints = self.solver_stack.pop()
                self.push_count -= 1

    def assertions(self):
        """Get current assertions."""
        return self.assertions_list

    def reset(self):
        """Reset the solver."""
        self.constraints.clear()
        self.assertions_list.clear()
        self.push_count = 0
        self.solver_stack.clear()

    def set_timeout(self, timeout: int):
        """Set solver timeout."""
        self.timeout_value = timeout

    def set(self, param: str, value: Any):
        """Set solver parameter."""
        self.set_params[param] = value
        if param == "timeout":
            self.timeout_value = value


class MockZ3:
    """Mock Z3 module for testing."""

    @staticmethod
    def BitVec(name: str, size: int) -> MockZ3BitVec:  # noqa: N802
        """Create a mock BitVec."""
        return MockZ3BitVec(name, size)

    @staticmethod
    def BitVecVal(value: int, size: int) -> MockZ3BitVec:  # noqa: N802
        """Create a mock BitVec with value."""
        return MockZ3BitVec(f"val_{value}", size, value)

    @staticmethod
    def Int(name: str) -> MockZ3Expr:  # noqa: N802
        """Create a mock Int."""
        return MockZ3Expr(name)

    @staticmethod
    def IntVal(value: int) -> MockZ3Expr:  # noqa: N802
        """Create a mock Int with value."""
        return MockZ3Expr(f"val_{value}", value)

    @staticmethod
    def Bool(name: str) -> MockZ3Expr:  # noqa: N802
        """Create a mock Bool."""
        return MockZ3Expr(name)

    @staticmethod
    def BoolVal(value: bool) -> MockZ3Expr:  # noqa: N802
        """Create a mock Bool with value."""
        return MockZ3Expr(f"val_{value}", value)

    @staticmethod
    def And(*args) -> MockZ3Expr:  # noqa: N802
        """Create And expression."""
        if len(args) == 0:
            return MockZ3Expr("True", True)
        if len(args) == 1:
            return args[0]
        return MockZ3Expr(f"And({', '.join(str(arg) for arg in args)})")

    @staticmethod
    def Or(*args) -> MockZ3Expr:  # noqa: N802
        """Create Or expression."""
        if len(args) == 0:
            return MockZ3Expr("False", False)
        if len(args) == 1:
            return args[0]
        return MockZ3Expr(f"Or({', '.join(str(arg) for arg in args)})")

    @staticmethod
    def Not(expr) -> MockZ3Expr:  # noqa: N802
        """Create Not expression."""
        return MockZ3Expr(f"Not({expr})")

    @staticmethod
    def Implies(a, b) -> MockZ3Expr:  # noqa: N802
        """Create Implies expression."""
        return MockZ3Expr(f"Implies({a}, {b})")

    @staticmethod
    def If(cond, true_expr, false_expr) -> MockZ3Expr:  # noqa: N802
        """Create If-Then-Else expression."""
        return MockZ3Expr(f"If({cond}, {true_expr}, {false_expr})")

    @staticmethod
    def Solver() -> MockZ3Solver:  # noqa: N802
        """Create a mock solver."""
        return MockZ3Solver()

    @staticmethod
    def sat():
        """Return sat result."""
        return "sat"

    @staticmethod
    def unsat():
        """Return unsat result."""
        return "unsat"

    @staticmethod
    def unknown():
        """Return unknown result."""
        return "unknown"

    @staticmethod
    def is_expr(expr) -> bool:
        """Check if object is Z3 expression."""
        return isinstance(expr, MockZ3Expr)

    @staticmethod
    def is_true(expr) -> bool:
        """Check if expression is true."""
        return isinstance(expr, MockZ3Expr) and expr.value is True

    @staticmethod
    def is_false(expr) -> bool:
        """Check if expression is false."""
        return isinstance(expr, MockZ3Expr) and expr.value is False

    @staticmethod
    def simplify(expr):
        """Simplify expression (returns same in mock)."""
        return expr


def create_mock_z3_module(solver_result: str = "sat", model_values: Union[dict[str, Any], None] = None):
    """
    Create a complete mock Z3 module for patching.

    Args:
        solver_result: Default result for solver.check()
        model_values: Default model values

    Returns:
        Mock module that can be used with patch()
    """
    mock_z3 = MagicMock()

    # Set up module attributes
    mock_z3.BitVec = MockZ3.BitVec
    mock_z3.BitVecVal = MockZ3.BitVecVal
    mock_z3.Int = MockZ3.Int
    mock_z3.IntVal = MockZ3.IntVal
    mock_z3.Bool = MockZ3.Bool
    mock_z3.BoolVal = MockZ3.BoolVal
    mock_z3.And = MockZ3.And
    mock_z3.Or = MockZ3.Or
    mock_z3.Not = MockZ3.Not
    mock_z3.Implies = MockZ3.Implies
    mock_z3.If = MockZ3.If
    mock_z3.sat = MockZ3.sat
    mock_z3.unsat = MockZ3.unsat
    mock_z3.unknown = MockZ3.unknown
    mock_z3.is_expr = MockZ3.is_expr
    mock_z3.is_true = MockZ3.is_true
    mock_z3.is_false = MockZ3.is_false
    mock_z3.simplify = MockZ3.simplify

    # Create solver factory
    def solver_factory():
        return MockZ3Solver(solver_result, model_values)

    mock_z3.Solver = solver_factory

    return mock_z3


class MockZ3Factory:
    """Factory for creating mock Z3 components with configurable behavior.

    Supports different modes for unit and integration testing:
    - 'unit': Minimal mocks for fast unit tests
    - 'integration': Full-featured mocks for integration tests
    - 'full': Complete Z3 API compatibility (for future use)
    """

    @staticmethod
    def create_solver(
        mode: Literal["unit", "integration", "full"] = "unit",
        result: str = "sat",
        model_values: Union[dict[str, Any], None] = None,
    ) -> MockZ3Solver:
        """Create a mock solver configured for the specified testing mode.

        Args:
            mode: Testing mode - 'unit', 'integration', or 'full'
            result: Default result for solver.check() - "sat", "unsat", or "unknown"
            model_values: Values to return in the model when sat

        Returns:
            Configured MockZ3Solver instance
        """
        solver = MockZ3Solver(result, model_values)

        if mode == "integration":
            # Add integration-specific features
            solver._mode = "integration"
            # Integration tests may need more realistic behavior
            solver._check_count = 0
            solver._original_check = solver.check

            def tracked_check(*assumptions):
                solver._check_count += 1
                return solver._original_check(*assumptions)

            solver.check = tracked_check

        elif mode == "full":
            # Future: Add full Z3 API compatibility
            solver._mode = "full"

        return solver

    @staticmethod
    def create_bitvec(
        name: str, size: int, value: Union[int, None] = None, mode: Literal["unit", "integration", "full"] = "unit"
    ) -> MockZ3BitVec:
        """Create a mock BitVec configured for the specified testing mode.

        Args:
            name: Name of the bitvector
            size: Size in bits
            value: Optional initial value
            mode: Testing mode

        Returns:
            Configured MockZ3BitVec instance
        """
        if mode == "integration":
            # Use integration-specific class with extended operations
            return MockZ3BitVecIntegration(name, size, value)

        return MockZ3BitVec(name, size, value)

    @staticmethod
    def create_bitvec_val(value: int, size: int, mode: Literal["unit", "integration", "full"] = "unit") -> MockZ3BitVec:
        """Create a mock BitVecVal with a specific value.

        Args:
            value: The integer value
            size: Size in bits
            mode: Testing mode

        Returns:
            Configured MockZ3BitVec instance with value
        """
        return MockZ3Factory.create_bitvec(f"val_{value}", size, value, mode)

    @staticmethod
    def create_z3_module(
        mode: Literal["unit", "integration", "full"] = "unit",
        solver_result: str = "sat",
        model_values: Union[dict[str, Any], None] = None,
    ) -> MagicMock:
        """Create a complete mock Z3 module for the specified testing mode.

        Args:
            mode: Testing mode
            solver_result: Default result for solver.check()
            model_values: Default model values

        Returns:
            Mock module configured for the specified mode
        """
        mock_z3 = create_mock_z3_module(solver_result, model_values)

        if mode == "integration":
            # Add integration-specific Z3 functions
            mock_z3.Extract = lambda high, low, expr: MagicMock(high=high, low=low, expr=expr)
            mock_z3.Concat = lambda *args: MagicMock(args=args)
            mock_z3.UDiv = lambda a, b: MagicMock(a=a, b=b)
            mock_z3.URem = lambda a, b: MagicMock(a=a, b=b)
            mock_z3.ULT = lambda a, b: MagicMock(a=a, b=b)
            mock_z3.ULE = lambda a, b: MagicMock(a=a, b=b)
            mock_z3.UGT = lambda a, b: MagicMock(a=a, b=b)
            mock_z3.UGE = lambda a, b: MagicMock(a=a, b=b)

            # Override Solver factory to use integration mode
            def solver_factory():
                return MockZ3Factory.create_solver(mode="integration", result=solver_result, model_values=model_values)

            mock_z3.Solver = solver_factory

            # Override BitVec factories to use integration mode
            mock_z3.BitVec = lambda name, size: MockZ3Factory.create_bitvec(name, size, mode="integration")
            mock_z3.BitVecVal = lambda value, size: MockZ3Factory.create_bitvec_val(value, size, mode="integration")

        return mock_z3


# Utility functions for common testing scenarios
def create_sat_solver(model_values: Union[dict[str, Any], None] = None) -> MockZ3Solver:
    """Create a solver that always returns SAT."""
    return MockZ3Factory.create_solver("unit", "sat", model_values)


def create_unsat_solver() -> MockZ3Solver:
    """Create a solver that always returns UNSAT."""
    return MockZ3Factory.create_solver("unit", "unsat")


def create_unknown_solver() -> MockZ3Solver:
    """Create a solver that always returns UNKNOWN."""
    return MockZ3Factory.create_solver("unit", "unknown")


def create_conditional_solver(condition_func) -> MockZ3Solver:
    """Create a solver with conditional behavior."""

    class ConditionalSolver(MockZ3Solver):
        def check(self, *assumptions):
            if condition_func(self.constraints):
                return "sat"
            return "unsat"

    return ConditionalSolver()
