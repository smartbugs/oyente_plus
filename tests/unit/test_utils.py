"""Unit tests for utils module.

Tests various utility functions used throughout the Oyente+ codebase
including mathematical operations, symbolic operations, and data structures.
Note: File I/O and subprocess tests moved to tests/integration/.
"""

from unittest.mock import Mock
from unittest.mock import patch

import pytest
from z3 import BitVec
from z3 import Z3Exception
from z3 import sat
from z3 import unsat

from oyente import utils


@pytest.mark.unit
class TestMathematicalUtils:
    """Test mathematical utility functions."""

    def test_ceil32_divisible_by_32(self):
        """Test ceil32 with numbers divisible by 32."""
        assert utils.ceil32(0) == 0
        assert utils.ceil32(32) == 32
        assert utils.ceil32(64) == 64
        assert utils.ceil32(96) == 96

    def test_ceil32_not_divisible_by_32(self):
        """Test ceil32 with numbers not divisible by 32."""
        assert utils.ceil32(1) == 32
        assert utils.ceil32(31) == 32
        assert utils.ceil32(33) == 64
        assert utils.ceil32(63) == 64
        assert utils.ceil32(65) == 96

    def test_ceil32_large_numbers(self):
        """Test ceil32 with large numbers."""
        assert utils.ceil32(1000) == 1024  # 32 * 32
        assert utils.ceil32(1023) == 1024
        assert utils.ceil32(1024) == 1024
        assert utils.ceil32(1025) == 1056

    def test_to_unsigned_positive_numbers(self):
        """Test to_unsigned with positive numbers."""
        assert utils.to_unsigned(0) == 0
        assert utils.to_unsigned(100) == 100
        assert utils.to_unsigned(2**255) == 2**255

    def test_to_unsigned_negative_numbers(self):
        """Test to_unsigned with negative numbers."""
        assert utils.to_unsigned(-1) == 2**256 - 1
        assert utils.to_unsigned(-100) == 2**256 - 100
        assert utils.to_unsigned(-(2**255)) == 2**255

    def test_to_signed_small_positive_numbers(self):
        """Test to_signed with numbers in positive range."""
        assert utils.to_signed(0) == 0
        assert utils.to_signed(100) == 100
        assert utils.to_signed(2 ** (256 - 1) - 1) == 2 ** (256 - 1) - 1

    def test_to_signed_large_numbers(self):
        """Test to_signed with numbers that should be negative."""
        assert utils.to_signed(2**256 - 1) == -1
        assert utils.to_signed(2**256 - 100) == -100
        # At exactly 2^255, should remain positive (condition is > not >=)
        assert utils.to_signed(2 ** (256 - 1)) == 2 ** (256 - 1)
        # One more than 2^255 should become negative
        assert utils.to_signed(2 ** (256 - 1) + 1) == -(2 ** (256 - 1) - 1)


@pytest.mark.unit
class TestSymbolicOperations:
    """Test symbolic operation utility functions."""

    def test_is_symbolic_with_integers(self):
        """Test isSymbolic returns False for integer types."""
        assert not utils.isSymbolic(0)
        assert not utils.isSymbolic(100)
        assert not utils.isSymbolic(-50)

    def test_is_symbolic_with_z3_expressions(self):
        """Test isSymbolic returns True for Z3 expressions."""
        x = BitVec("x", 256)
        assert utils.isSymbolic(x)
        assert utils.isSymbolic(x + 1)

    def test_is_real_with_integers(self):
        """Test isReal returns True for integer types."""
        assert utils.isReal(0)
        assert utils.isReal(100)
        assert utils.isReal(-50)

    def test_is_real_with_z3_expressions(self):
        """Test isReal returns False for Z3 expressions."""
        x = BitVec("x", 256)
        assert not utils.isReal(x)
        assert not utils.isReal(x + 1)

    def test_is_all_real_all_integers(self):
        """Test isAllReal returns True when all arguments are integers."""
        assert utils.isAllReal(1, 2, 3)
        assert utils.isAllReal(0)
        assert utils.isAllReal(-1, 0, 1)

    def test_is_all_real_mixed_types(self):
        """Test isAllReal returns False when any argument is symbolic."""
        x = BitVec("x", 256)
        assert not utils.isAllReal(1, 2, x)
        assert not utils.isAllReal(x)
        assert not utils.isAllReal(1, x, 3)

    def test_to_symbolic_with_integer(self):
        """Test to_symbolic converts integers to BitVecVal."""
        result = utils.to_symbolic(42)
        assert str(result) == "42"
        # Should be a Z3 BitVecVal
        assert hasattr(result, "as_long")

    def test_to_symbolic_with_z3_expression(self):
        """Test to_symbolic returns Z3 expressions unchanged."""
        x = BitVec("x", 256)
        result = utils.to_symbolic(x)
        assert result is x


@pytest.mark.unit
class TestZ3HelperFunctions:
    """Test Z3 solver helper functions."""

    @patch("oyente.utils.unknown", "unknown_reason")
    def test_check_sat_with_sat_result(self, mock_z3_solver):
        """Test check_sat with satisfiable solver."""
        mock_solver = Mock()
        mock_solver.check.return_value = sat

        result = utils.check_sat(mock_solver)
        assert result == sat

    @patch("oyente.utils.unknown", "unknown_reason")
    def test_check_sat_with_unsat_result(self, mock_z3_solver):
        """Test check_sat with unsatisfiable solver."""
        mock_solver = Mock()
        mock_solver.check.return_value = unsat

        result = utils.check_sat(mock_solver)
        assert result == unsat

    @patch("oyente.utils.unknown", "unknown_reason")
    def test_check_sat_with_unknown_result(self, mock_z3_solver):
        """Test check_sat with unknown result raises exception."""
        mock_solver = Mock()
        mock_solver.check.return_value = "unknown_reason"
        mock_solver.reason_unknown.return_value = "timeout"

        with pytest.raises(Z3Exception):
            utils.check_sat(mock_solver)

    def test_check_sat_with_exception_pop_enabled(self):
        """Test check_sat pops solver on exception when pop_if_exception=True."""
        mock_solver = Mock()
        mock_solver.check.side_effect = Exception("solver error")

        with pytest.raises(Exception, match="solver error"):
            utils.check_sat(mock_solver, pop_if_exception=True)

        mock_solver.pop.assert_called_once()

    def test_check_sat_with_exception_pop_disabled(self):
        """Test check_sat doesn't pop solver when pop_if_exception=False."""
        mock_solver = Mock()
        mock_solver.check.side_effect = Exception("solver error")

        with pytest.raises(Exception, match="solver error"):
            utils.check_sat(mock_solver, pop_if_exception=False)

        mock_solver.pop.assert_not_called()


@pytest.mark.unit
class TestDataStructureUtils:
    """Test data structure utility functions."""

    def test_custom_deepcopy_simple_dict(self):
        """Test custom_deepcopy with simple dictionary."""
        original = {"a": 1, "b": 2, "c": 3}
        copy = utils.custom_deepcopy(original)

        assert copy == original
        assert copy is not original  # Different objects

        # Modify copy shouldn't affect original
        copy["a"] = 99
        assert original["a"] == 1

    def test_custom_deepcopy_nested_dict(self):
        """Test custom_deepcopy with nested dictionaries."""
        original = {"outer": {"inner": {"deep": 42}}, "simple": 10}
        copy = utils.custom_deepcopy(original)

        assert copy == original
        assert copy is not original
        assert copy["outer"] is not original["outer"]
        assert copy["outer"]["inner"] is not original["outer"]["inner"]

        # Modify nested value
        copy["outer"]["inner"]["deep"] = 99
        assert original["outer"]["inner"]["deep"] == 42

    def test_custom_deepcopy_with_lists(self):
        """Test custom_deepcopy with lists."""
        original = {"list": [1, 2, 3], "nested": {"list": [4, 5, 6]}}
        copy = utils.custom_deepcopy(original)

        assert copy == original
        assert copy["list"] is not original["list"]
        assert copy["nested"]["list"] is not original["nested"]["list"]

        # Modify list
        copy["list"].append(99)
        assert len(original["list"]) == 3

    def test_custom_deepcopy_mixed_types(self):
        """Test custom_deepcopy with mixed data types."""
        original = {"string": "test", "number": 42, "list": [1, 2, 3], "dict": {"nested": True}, "none": None}
        copy = utils.custom_deepcopy(original)

        assert copy == original
        assert copy is not original
        assert copy["list"] is not original["list"]
        assert copy["dict"] is not original["dict"]


@pytest.mark.unit
class TestVariableUtils:
    """Test variable analysis utility functions."""

    def test_is_storage_var_with_z3_variable(self):
        """Test is_storage_var with Z3 variable."""
        # Mock Z3 variable with storage name
        mock_var = Mock()
        mock_var.decl.return_value.name.return_value = "Ia_store_0"

        assert utils.is_storage_var(mock_var)

    def test_is_storage_var_with_string(self):
        """Test is_storage_var with string variable name."""
        assert utils.is_storage_var("Ia_store_5")
        assert utils.is_storage_var("Ia_store_balance")
        assert not utils.is_storage_var("regular_var")
        assert not utils.is_storage_var("some_other_var")

    def test_is_storage_var_non_storage_names(self):
        """Test is_storage_var returns False for non-storage variables."""
        mock_var = Mock()
        mock_var.decl.return_value.name.return_value = "regular_var"

        assert not utils.is_storage_var(mock_var)
        assert not utils.is_storage_var("temp_var")
        assert not utils.is_storage_var("stack_var")

    def test_copy_global_values(self):
        """Test copy_global_values extracts Ia value."""
        global_state = {"Ia": "address_value", "Is": "sender_value", "other": "other_value"}

        result = utils.copy_global_values(global_state)
        assert result == "address_value"

    @patch("oyente.utils.get_vars")
    def test_is_in_expr_variable_present(self, mock_get_vars):
        """Test is_in_expr when variable is present in expression."""
        # Mock variables in expression
        mock_var1 = Mock()
        mock_var1.decl.return_value.name.return_value = "target_var"
        mock_var2 = Mock()
        mock_var2.decl.return_value.name.return_value = "other_var"

        mock_get_vars.return_value = [mock_var1, mock_var2]

        result = utils.is_in_expr("target_var", "mock_expr")
        assert result is True

    @patch("oyente.utils.get_vars")
    def test_is_in_expr_variable_absent(self, mock_get_vars):
        """Test is_in_expr when variable is not present in expression."""
        mock_var = Mock()
        mock_var.decl.return_value.name.return_value = "other_var"

        mock_get_vars.return_value = [mock_var]

        result = utils.is_in_expr("target_var", "mock_expr")
        assert result is False

    @patch("oyente.utils.get_vars")
    def test_has_storage_vars_with_storage_variables(self, mock_get_vars):
        """Test has_storage_vars when expression contains storage variables."""
        storage_var = Mock()
        other_var = Mock()

        mock_get_vars.return_value = [storage_var, other_var]
        storage_vars = [storage_var]

        result = utils.has_storage_vars("mock_expr", storage_vars)
        assert result is True

    @patch("oyente.utils.get_vars")
    def test_has_storage_vars_without_storage_variables(self, mock_get_vars):
        """Test has_storage_vars when expression has no storage variables."""
        var1 = Mock()
        var2 = Mock()
        storage_var = Mock()

        mock_get_vars.return_value = [var1, var2]
        storage_vars = [storage_var]

        result = utils.has_storage_vars("mock_expr", storage_vars)
        assert result is False

    def test_get_storage_position_with_integer_position(self):
        """Test get_storage_position with integer storage position."""
        mock_var = Mock()
        mock_var.decl.return_value.name.return_value = "Ia_store-5-var"

        result = utils.get_storage_position(mock_var)
        assert result == 5

    def test_get_storage_position_with_string_position(self):
        """Test get_storage_position with non-integer position."""
        mock_var = Mock()
        mock_var.decl.return_value.name.return_value = "Ia_store-slot_a-var"

        result = utils.get_storage_position(mock_var)
        assert result == "slot_a"

    def test_get_storage_position_with_string_input(self):
        """Test get_storage_position with string variable name."""
        result = utils.get_storage_position("Ia_store-10-balance")
        assert result == 10

        result = utils.get_storage_position("Ia_store-key-value")
        assert result == "key"


# File operations and subprocess tests moved to tests/integration/test_file_operations.py
# Contract info tests moved to tests/integration/test_file_operations.py


@pytest.mark.unit
class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling scenarios."""

    def test_ceil32_with_zero(self):
        """Test ceil32 handles zero correctly."""
        assert utils.ceil32(0) == 0

    def test_to_unsigned_boundary_values(self):
        """Test to_unsigned with boundary values."""
        # Test largest negative value
        assert utils.to_unsigned(-(2**255)) == 2**255

        # Test -1 (common case)
        assert utils.to_unsigned(-1) == 2**256 - 1

    def test_to_signed_boundary_values(self):
        """Test to_signed with boundary values."""
        # Test exactly at the boundary (2^255 should remain positive)
        boundary = 2 ** (256 - 1)
        assert utils.to_signed(boundary) == boundary
        assert utils.to_signed(boundary - 1) == boundary - 1
        # Test just above the boundary (should become negative)
        assert utils.to_signed(boundary + 1) == -(boundary - 1)

    def test_custom_deepcopy_empty_dict(self):
        """Test custom_deepcopy with empty dictionary."""
        original = {}
        copy = utils.custom_deepcopy(original)

        assert copy == original
        assert copy is not original

    def test_custom_deepcopy_with_none_values(self):
        """Test custom_deepcopy preserves None values."""
        original = {"a": None, "b": {"c": None}}
        copy = utils.custom_deepcopy(original)

        assert copy == original
        assert copy["a"] is None
        assert copy["b"]["c"] is None

    def test_get_storage_position_malformed_names(self):
        """Test get_storage_position with malformed variable names."""
        # Test with insufficient parts - this will raise an IndexError
        with pytest.raises(IndexError):
            utils.get_storage_position("Ia_store")

    @patch("oyente.utils.get_vars")
    def test_get_all_vars_mixed_expressions(self, mock_get_vars):
        """Test get_all_vars with mix of expressions and non-expressions."""
        # Mock some expressions and some non-expressions
        expr1 = Mock()
        expr2 = "not_an_expression"
        expr3 = Mock()

        var1 = Mock()
        var2 = Mock()

        def mock_is_expr(obj):
            return hasattr(obj, "mock_calls")  # Mock objects have this attribute

        def mock_get_vars_side_effect(expr):
            if expr is expr1:
                return [var1]
            elif expr is expr3:
                return [var2]
            return []

        mock_get_vars.side_effect = mock_get_vars_side_effect

        with patch("oyente.utils.is_expr", side_effect=mock_is_expr):
            result = utils.get_all_vars([expr1, expr2, expr3])

        assert var1 in result
        assert var2 in result

    def test_is_all_real_empty_args(self):
        """Test isAllReal with no arguments."""
        assert utils.isAllReal()  # Should return True for empty args

    def test_type_handling_edge_cases(self):
        """Test type checking functions with edge cases."""
        # Test with None - None is not an integer type, so it's considered symbolic
        assert utils.isSymbolic(None)
        assert not utils.isReal(None)

        # Test with boolean - In Python 3, bool is a subclass of int
        assert not utils.isSymbolic(True)
        assert utils.isReal(True)  # Booleans are integer_types in Python 3

    @pytest.mark.parametrize(
        "input_val,expected", [(0, 0), (31, 32), (32, 32), (33, 64), (1000, 1024), (1024, 1024), (1025, 1056)]
    )
    def test_ceil32_parametrized(self, input_val, expected):
        """Parametrized test for ceil32 function."""
        assert utils.ceil32(input_val) == expected

    def test_memory_efficiency_large_dict(self):
        """Test that custom_deepcopy is memory efficient with large structures."""
        # Create a large nested structure
        large_dict = {}
        for i in range(100):
            large_dict[f"key_{i}"] = {"list": list(range(50)), "nested": {"deep": list(range(20))}}

        # Should not raise memory errors
        copy = utils.custom_deepcopy(large_dict)

        # Verify it's a proper copy
        assert copy == large_dict
        assert copy is not large_dict

        # Verify deep copying worked
        copy["key_0"]["list"].append(999)
        assert 999 not in large_dict["key_0"]["list"]
