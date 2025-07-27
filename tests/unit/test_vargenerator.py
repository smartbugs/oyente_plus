"""Unit tests for vargenerator module.

Tests the Generator class that creates unique variable names for
symbolic execution during EVM bytecode analysis.
"""

import pytest

from oyente.vargenerator import Generator


class TestGenerator:
    """Test the Generator class for variable name generation."""

    def test_generator_initialization(self):
        """Test generator initializes with zero counters."""
        gen = Generator()
        assert gen.countstack == 0
        assert gen.countdata == 0
        assert gen.count == 0

    def test_gen_stack_var_unique_names(self):
        """Test that gen_stack_var generates unique stack variable names."""
        gen = Generator()

        # Generate multiple stack variables
        vars = [gen.gen_stack_var() for _ in range(5)]

        # Check format and uniqueness
        expected = ["s1", "s2", "s3", "s4", "s5"]
        assert vars == expected
        assert len(set(vars)) == len(vars)  # All unique
        assert gen.countstack == 5

    def test_gen_stack_var_incremental(self):
        """Test that stack variable counter increments correctly."""
        gen = Generator()

        assert gen.gen_stack_var() == "s1"
        assert gen.gen_stack_var() == "s2"
        assert gen.gen_stack_var() == "s3"
        assert gen.countstack == 3

    def test_gen_data_var_unique_names(self):
        """Test that gen_data_var generates unique data variable names."""
        gen = Generator()

        # Generate multiple data variables
        vars = [gen.gen_data_var() for _ in range(3)]

        # Check format and uniqueness
        expected = ["Id_1", "Id_2", "Id_3"]
        assert vars == expected
        assert len(set(vars)) == len(vars)  # All unique
        assert gen.countdata == 3

    def test_gen_data_var_with_position_parameter(self):
        """Test that gen_data_var ignores position parameter."""
        gen = Generator()

        # Position parameter should be ignored
        assert gen.gen_data_var(None) == "Id_1"
        assert gen.gen_data_var(5) == "Id_2"
        assert gen.gen_data_var("test") == "Id_3"
        assert gen.countdata == 3

    def test_gen_data_size_constant(self):
        """Test that gen_data_size returns constant string."""
        gen = Generator()

        # Should always return the same constant
        assert gen.gen_data_size() == "Id_size"
        assert gen.gen_data_size() == "Id_size"

        # Should not affect counters
        assert gen.countdata == 0
        assert gen.count == 0

    def test_gen_mem_var_with_different_addresses(self):
        """Test gen_mem_var with different address types."""
        gen = Generator()

        # Test with integer address
        assert gen.gen_mem_var(100) == "mem_100"

        # Test with string address
        assert gen.gen_mem_var("0x123") == "mem_0x123"

        # Test with hex integer
        assert gen.gen_mem_var(0xFF) == "mem_255"

    def test_gen_arbitrary_var_unique_names(self):
        """Test that gen_arbitrary_var generates unique names."""
        gen = Generator()

        vars = [gen.gen_arbitrary_var() for _ in range(3)]

        expected = ["some_var_1", "some_var_2", "some_var_3"]
        assert vars == expected
        assert len(set(vars)) == len(vars)  # All unique
        assert gen.count == 3

    def test_gen_arbitrary_address_var_unique_names(self):
        """Test that gen_arbitrary_address_var generates unique names."""
        gen = Generator()

        vars = [gen.gen_arbitrary_address_var() for _ in range(3)]

        expected = ["some_address_1", "some_address_2", "some_address_3"]
        assert vars == expected
        assert len(set(vars)) == len(vars)  # All unique
        assert gen.count == 3

    def test_gen_owner_store_var_formatting(self):
        """Test gen_owner_store_var with different parameters."""
        gen = Generator()

        # Test with position and var_name
        assert gen.gen_owner_store_var(0, "balance") == "Ia_store-0-balance"
        assert gen.gen_owner_store_var(5, "owner") == "Ia_store-5-owner"

        # Test with string position
        assert gen.gen_owner_store_var("slot1", "data") == "Ia_store-slot1-data"

        # Test with empty var_name
        assert gen.gen_owner_store_var(10, "") == "Ia_store-10-"

        # Test without var_name (default empty string)
        assert gen.gen_owner_store_var(20) == "Ia_store-20-"

    def test_gen_gas_var_unique_names(self):
        """Test that gen_gas_var generates unique names."""
        gen = Generator()

        vars = [gen.gen_gas_var() for _ in range(3)]

        expected = ["gas_1", "gas_2", "gas_3"]
        assert vars == expected
        assert len(set(vars)) == len(vars)  # All unique
        assert gen.count == 3

    def test_gen_gas_price_var_constant(self):
        """Test that gen_gas_price_var returns constant string."""
        gen = Generator()

        assert gen.gen_gas_price_var() == "Ip"
        assert gen.gen_gas_price_var() == "Ip"

        # Should not affect counters
        assert gen.count == 0

    def test_gen_address_var_constant(self):
        """Test that gen_address_var returns constant string."""
        gen = Generator()

        assert gen.gen_address_var() == "Ia"
        assert gen.gen_address_var() == "Ia"

        # Should not affect counters
        assert gen.count == 0

    def test_gen_caller_var_constant(self):
        """Test that gen_caller_var returns constant string."""
        gen = Generator()

        assert gen.gen_caller_var() == "Is"
        assert gen.gen_caller_var() == "Is"

        # Should not affect counters
        assert gen.count == 0

    def test_gen_origin_var_constant(self):
        """Test that gen_origin_var returns constant string."""
        gen = Generator()

        assert gen.gen_origin_var() == "Io"
        assert gen.gen_origin_var() == "Io"

        # Should not affect counters
        assert gen.count == 0

    def test_gen_balance_var_unique_names(self):
        """Test that gen_balance_var generates unique names."""
        gen = Generator()

        vars = [gen.gen_balance_var() for _ in range(3)]

        expected = ["balance_1", "balance_2", "balance_3"]
        assert vars == expected
        assert len(set(vars)) == len(vars)  # All unique
        assert gen.count == 3

    def test_gen_code_var_with_parameters(self):
        """Test gen_code_var with different parameter types."""
        gen = Generator()

        # Test with integer parameters
        assert gen.gen_code_var(100, 50, 32) == "code_100_50_32"

        # Test with string parameters
        assert gen.gen_code_var("0x123", "pos", "bytes") == "code_0x123_pos_bytes"

        # Test with mixed parameters
        assert gen.gen_code_var(200, "0x10", 64) == "code_200_0x10_64"

    def test_gen_code_size_var_with_addresses(self):
        """Test gen_code_size_var with different address types."""
        gen = Generator()

        # Test with integer address
        assert gen.gen_code_size_var(100) == "code_size_100"

        # Test with string address
        assert gen.gen_code_size_var("0x456") == "code_size_0x456"

        # Test with hex integer
        assert gen.gen_code_size_var(0xABC) == "code_size_2748"

    def test_shared_count_counter(self):
        """Test that some methods share the same counter."""
        gen = Generator()

        # These methods should all use gen.count
        gen.gen_arbitrary_var()  # count = 1
        gen.gen_arbitrary_address_var()  # count = 2
        gen.gen_gas_var()  # count = 3
        gen.gen_balance_var()  # count = 4

        assert gen.count == 4

        # But separate counters for stack and data
        gen.gen_stack_var()  # countstack = 1
        gen.gen_data_var()  # countdata = 1

        assert gen.countstack == 1
        assert gen.countdata == 1
        assert gen.count == 4  # Unchanged

    def test_independent_counters(self):
        """Test that different variable types have independent counters."""
        gen = Generator()

        # Generate variables of different types
        stack_var = gen.gen_stack_var()  # countstack = 1
        data_var = gen.gen_data_var()  # countdata = 1
        arbitrary_var = gen.gen_arbitrary_var()  # count = 1

        assert stack_var == "s1"
        assert data_var == "Id_1"
        assert arbitrary_var == "some_var_1"

        # Check that counters are independent
        assert gen.countstack == 1
        assert gen.countdata == 1
        assert gen.count == 1

    def test_multiple_generators_independence(self):
        """Test that multiple Generator instances are independent."""
        gen1 = Generator()
        gen2 = Generator()

        # Generate variables with first generator
        gen1.gen_stack_var()
        gen1.gen_arbitrary_var()

        # Second generator should start from zero
        assert gen2.gen_stack_var() == "s1"
        assert gen2.gen_arbitrary_var() == "some_var_1"

        # First generator should continue its sequence
        assert gen1.gen_stack_var() == "s2"
        assert gen1.gen_arbitrary_var() == "some_var_2"

    def test_constant_methods_do_not_modify_state(self):
        """Test that constant methods don't modify generator state."""
        gen = Generator()

        initial_countstack = gen.countstack
        initial_countdata = gen.countdata
        initial_count = gen.count

        # Call constant methods multiple times
        for _ in range(5):
            gen.gen_data_size()
            gen.gen_gas_price_var()
            gen.gen_address_var()
            gen.gen_caller_var()
            gen.gen_origin_var()

        # State should be unchanged
        assert gen.countstack == initial_countstack
        assert gen.countdata == initial_countdata
        assert gen.count == initial_count

    def test_parameter_conversion_to_string(self):
        """Test that parameters are properly converted to strings."""
        gen = Generator()

        # Test with various types that need string conversion
        test_cases = [
            (0, "mem_0"),
            (123, "mem_123"),
            (-5, "mem_-5"),
            (0xFF, "mem_255"),
            ("hello", "mem_hello"),
            ("0x123abc", "mem_0x123abc"),
        ]

        for input_val, expected in test_cases:
            result = gen.gen_mem_var(input_val)
            assert result == expected

    def test_edge_cases_for_owner_store_var(self):
        """Test edge cases for gen_owner_store_var method."""
        gen = Generator()

        # Test with special characters in position
        assert gen.gen_owner_store_var("test-pos", "var") == "Ia_store-test-pos-var"

        # Test with None as var_name (should use default empty string)
        result = gen.gen_owner_store_var(5)
        assert result == "Ia_store-5-"

        # Test with very long strings
        long_pos = "a" * 100
        long_var = "b" * 100
        expected = f"Ia_store-{long_pos}-{long_var}"
        assert gen.gen_owner_store_var(long_pos, long_var) == expected

    @pytest.mark.parametrize("count", [1, 10, 100, 1000])
    def test_large_counter_values(self, count):
        """Test generator with large counter values."""
        gen = Generator()

        # Set counter to large value
        gen.count = count - 1

        result = gen.gen_arbitrary_var()
        expected = f"some_var_{count}"
        assert result == expected
        assert gen.count == count

    def test_type_annotations_and_return_types(self):
        """Test that methods return correct types as per annotations."""
        gen = Generator()

        # All methods should return strings
        assert isinstance(gen.gen_stack_var(), str)
        assert isinstance(gen.gen_data_var(), str)
        assert isinstance(gen.gen_data_size(), str)
        assert isinstance(gen.gen_mem_var(0), str)
        assert isinstance(gen.gen_arbitrary_var(), str)
        assert isinstance(gen.gen_arbitrary_address_var(), str)
        assert isinstance(gen.gen_owner_store_var(0), str)
        assert isinstance(gen.gen_gas_var(), str)
        assert isinstance(gen.gen_gas_price_var(), str)
        assert isinstance(gen.gen_address_var(), str)
        assert isinstance(gen.gen_caller_var(), str)
        assert isinstance(gen.gen_origin_var(), str)
        assert isinstance(gen.gen_balance_var(), str)
        assert isinstance(gen.gen_code_var(0, 0, 0), str)
        assert isinstance(gen.gen_code_size_var(0), str)

    def test_stress_test_uniqueness(self):
        """Stress test to ensure uniqueness under high load."""
        gen = Generator()

        # Generate large number of variables
        stack_vars = [gen.gen_stack_var() for _ in range(1000)]
        data_vars = [gen.gen_data_var() for _ in range(1000)]
        arbitrary_vars = [gen.gen_arbitrary_var() for _ in range(1000)]

        # Check uniqueness within each type
        assert len(set(stack_vars)) == len(stack_vars)
        assert len(set(data_vars)) == len(data_vars)
        assert len(set(arbitrary_vars)) == len(arbitrary_vars)

        # Check that patterns are correct
        assert stack_vars[0] == "s1"
        assert stack_vars[-1] == "s1000"
        assert data_vars[0] == "Id_1"
        assert data_vars[-1] == "Id_1000"
        assert arbitrary_vars[0] == "some_var_1"
        assert arbitrary_vars[-1] == "some_var_1000"
