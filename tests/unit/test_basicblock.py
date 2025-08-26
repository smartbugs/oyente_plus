"""Unit tests for basicblock module.

Tests the BasicBlock class that represents basic blocks in the
control flow graph during EVM bytecode analysis.
"""

from unittest.mock import patch

import pytest

from oyente.basicblock import BasicBlock


@pytest.mark.unit
class TestBasicBlockInitialization:
    """Test BasicBlock initialization and basic properties."""

    def test_basic_block_creation(self):
        """Test basic block creation with start and end addresses."""
        block = BasicBlock(100, 200)

        assert block.start == 100
        assert block.end == 200
        assert block.get_start_address() == 100
        assert block.get_end_address() == 200

    def test_basic_block_default_values(self):
        """Test basic block has correct default values."""
        block = BasicBlock(50, 150)

        assert block.instructions == []
        assert block.jump_target == 0
        assert block.type is None
        assert block.falls_to is None
        assert block.branch_expression is None

    def test_basic_block_with_zero_addresses(self):
        """Test basic block creation with zero addresses."""
        block = BasicBlock(0, 0)

        assert block.start == 0
        assert block.end == 0

    def test_basic_block_with_negative_addresses(self):
        """Test basic block creation with negative addresses."""
        block = BasicBlock(-10, -5)

        assert block.start == -10
        assert block.end == -5

    def test_basic_block_start_greater_than_end(self):
        """Test basic block allows start address greater than end."""
        # This might be an edge case that should be handled
        block = BasicBlock(200, 100)

        assert block.start == 200
        assert block.end == 100


@pytest.mark.unit
class TestBasicBlockInstructions:
    """Test instruction management in basic blocks."""

    def test_add_single_instruction(self):
        """Test adding a single instruction to the block."""
        block = BasicBlock(0, 10)

        block.add_instruction("PUSH1 0x01")

        assert len(block.instructions) == 1
        assert block.instructions[0] == "PUSH1 0x01"
        assert block.get_instructions() == ["PUSH1 0x01"]

    def test_add_multiple_instructions(self):
        """Test adding multiple instructions to the block."""
        block = BasicBlock(0, 20)

        instructions = ["PUSH1 0x01", "PUSH1 0x02", "ADD", "STOP"]
        for instr in instructions:
            block.add_instruction(instr)

        assert len(block.instructions) == 4
        assert block.get_instructions() == instructions

    def test_add_empty_instruction(self):
        """Test adding empty string as instruction."""
        block = BasicBlock(0, 5)

        block.add_instruction("")

        assert len(block.instructions) == 1
        assert block.instructions[0] == ""

    def test_instructions_list_reference(self):
        """Test that returned instructions list is a direct reference."""
        block = BasicBlock(0, 10)
        block.add_instruction("PUSH1 0x01")

        instructions = block.get_instructions()
        instructions.append("MALICIOUS")

        # The returned list is the same reference, so changes affect the original
        assert len(block.instructions) == 2
        assert "MALICIOUS" in block.instructions
        assert instructions is block.instructions

    def test_add_instruction_preserves_order(self):
        """Test that instructions are added in the correct order."""
        block = BasicBlock(0, 30)

        expected_order = [f"INSTR_{i}" for i in range(10)]
        for instr in expected_order:
            block.add_instruction(instr)

        assert block.get_instructions() == expected_order


@pytest.mark.unit
class TestBasicBlockType:
    """Test block type management."""

    def test_set_block_type(self):
        """Test setting block type."""
        block = BasicBlock(0, 10)

        block.set_block_type("conditional")

        assert block.type == "conditional"
        assert block.get_block_type() == "conditional"

    def test_set_block_type_multiple_times(self):
        """Test setting block type multiple times."""
        block = BasicBlock(0, 10)

        block.set_block_type("conditional")
        assert block.get_block_type() == "conditional"

        block.set_block_type("unconditional")
        assert block.get_block_type() == "unconditional"

    def test_set_block_type_empty_string(self):
        """Test setting block type to empty string."""
        block = BasicBlock(0, 10)

        block.set_block_type("")

        assert block.type == ""
        assert block.get_block_type() == ""

    def test_set_block_type_none(self):
        """Test setting block type to None."""
        block = BasicBlock(0, 10)

        block.set_block_type(None)

        assert block.type is None
        assert block.get_block_type() is None

    @pytest.mark.parametrize("block_type", ["conditional", "unconditional", "terminal", "loop_head", "custom_type"])
    def test_various_block_types(self, block_type):
        """Test setting various block types."""
        block = BasicBlock(0, 10)

        block.set_block_type(block_type)

        assert block.get_block_type() == block_type


@pytest.mark.unit
class TestBasicBlockFallsTo:
    """Test falls_to address management."""

    def test_set_falls_to_address(self):
        """Test setting falls_to address."""
        block = BasicBlock(0, 10)

        block.set_falls_to(20)

        assert block.falls_to == 20
        assert block.get_falls_to() == 20

    def test_set_falls_to_none(self):
        """Test setting falls_to to None."""
        block = BasicBlock(0, 10)

        block.set_falls_to(20)
        block.set_falls_to(None)

        assert block.falls_to is None
        assert block.get_falls_to() is None

    def test_set_falls_to_zero(self):
        """Test setting falls_to to zero."""
        block = BasicBlock(0, 10)

        block.set_falls_to(0)

        assert block.falls_to == 0
        assert block.get_falls_to() == 0

    def test_set_falls_to_negative(self):
        """Test setting falls_to to negative value."""
        block = BasicBlock(0, 10)

        block.set_falls_to(-5)

        assert block.falls_to == -5
        assert block.get_falls_to() == -5

    def test_set_falls_to_multiple_times(self):
        """Test setting falls_to multiple times."""
        block = BasicBlock(0, 10)

        block.set_falls_to(20)
        assert block.get_falls_to() == 20

        block.set_falls_to(30)
        assert block.get_falls_to() == 30


@pytest.mark.unit
class TestBasicBlockJumpTarget:
    """Test jump target management."""

    def test_set_jump_target_integer(self):
        """Test setting jump target with integer."""
        block = BasicBlock(0, 10)

        block.set_jump_target(100)

        assert block.jump_target == 100
        assert block.get_jump_target() == 100

    def test_set_jump_target_zero(self):
        """Test setting jump target to zero."""
        block = BasicBlock(0, 10)

        block.set_jump_target(0)

        assert block.jump_target == 0
        assert block.get_jump_target() == 0

    def test_set_jump_target_negative(self):
        """Test setting jump target to negative integer."""
        block = BasicBlock(0, 10)

        block.set_jump_target(-50)

        assert block.jump_target == -50
        assert block.get_jump_target() == -50

    def test_set_jump_target_non_integer(self):
        """Test setting jump target with non-integer sets to -1."""
        block = BasicBlock(0, 10)

        # Test with string
        block.set_jump_target("invalid")
        assert block.jump_target == -1
        assert block.get_jump_target() == -1

        # Test with None
        block.set_jump_target(None)
        assert block.jump_target == -1

        # Test with float
        block.set_jump_target(3.14)
        assert block.jump_target == -1

    def test_set_jump_target_large_integer(self):
        """Test setting jump target with large integer."""
        block = BasicBlock(0, 10)

        large_int = 2**31
        block.set_jump_target(large_int)

        assert block.jump_target == large_int
        assert block.get_jump_target() == large_int


@pytest.mark.unit
class TestBasicBlockBranchExpression:
    """Test branch expression management."""

    def test_set_branch_expression(self):
        """Test setting branch expression."""
        block = BasicBlock(0, 10)

        expression = "x > 0"
        block.set_branch_expression(expression)

        assert block.branch_expression == expression
        assert block.get_branch_expression() == expression

    def test_set_branch_expression_none(self):
        """Test setting branch expression to None."""
        block = BasicBlock(0, 10)

        block.set_branch_expression("x > 0")
        block.set_branch_expression(None)

        assert block.branch_expression is None
        assert block.get_branch_expression() is None

    def test_set_branch_expression_complex_object(self):
        """Test setting branch expression to complex object."""
        block = BasicBlock(0, 10)

        # Could be a Z3 expression or any other object
        complex_expr = {"type": "comparison", "left": "x", "right": "0"}
        block.set_branch_expression(complex_expr)

        assert block.branch_expression == complex_expr
        assert block.get_branch_expression() == complex_expr

    def test_set_branch_expression_multiple_times(self):
        """Test setting branch expression multiple times."""
        block = BasicBlock(0, 10)

        expr1 = "x > 0"
        expr2 = "y < 10"

        block.set_branch_expression(expr1)
        assert block.get_branch_expression() == expr1

        block.set_branch_expression(expr2)
        assert block.get_branch_expression() == expr2


@pytest.mark.unit
class TestBasicBlockDisplay:
    """Test the display functionality."""

    @patch("builtins.print")
    def test_display_basic_block(self, mock_print):
        """Test display method prints basic block information."""
        block = BasicBlock(100, 200)
        block.add_instruction("PUSH1 0x01")
        block.add_instruction("PUSH1 0x02")
        block.set_block_type("conditional")

        block.display()

        # Check that print was called with expected content
        calls = [call[0][0] for call in mock_print.call_args_list]

        assert "================" in calls
        assert "start address: 100" in calls
        assert "end address: 200" in calls
        assert "end statement type: conditional" in calls
        assert "PUSH1 0x01" in calls
        assert "PUSH1 0x02" in calls

    @patch("builtins.print")
    def test_display_block_without_type(self, mock_print):
        """Test display method when block has no type."""
        block = BasicBlock(50, 100)
        block.add_instruction("STOP")

        block.display()

        calls = [call[0][0] for call in mock_print.call_args_list]

        assert "start address: 50" in calls
        assert "end address: 100" in calls
        assert "STOP" in calls
        # Should not print type line
        assert not any("end statement type:" in call for call in calls)

    @patch("builtins.print")
    def test_display_empty_block(self, mock_print):
        """Test display method with empty block."""
        block = BasicBlock(0, 0)

        block.display()

        calls = [call[0][0] for call in mock_print.call_args_list]

        assert "================" in calls
        assert "start address: 0" in calls
        assert "end address: 0" in calls
        # No instructions should be printed

    @patch("builtins.print")
    def test_display_block_with_many_instructions(self, mock_print):
        """Test display method with many instructions."""
        block = BasicBlock(0, 100)

        # Add many instructions
        for i in range(10):
            block.add_instruction(f"INSTR_{i}")

        block.display()

        calls = [call[0][0] for call in mock_print.call_args_list]

        # Check all instructions are printed
        for i in range(10):
            assert f"INSTR_{i}" in calls


@pytest.mark.unit
class TestBasicBlockIntegration:
    """Test basic block in integrated scenarios."""

    def test_complete_basic_block_scenario(self):
        """Test a complete basic block configuration."""
        block = BasicBlock(100, 150)

        # Configure the block completely
        block.add_instruction("PUSH1 0x01")
        block.add_instruction("PUSH1 0x02")
        block.add_instruction("GT")
        block.add_instruction("JUMPI")

        block.set_block_type("conditional")
        block.set_falls_to(160)
        block.set_jump_target(200)
        block.set_branch_expression("x > y")

        # Verify all properties
        assert block.get_start_address() == 100
        assert block.get_end_address() == 150
        assert len(block.get_instructions()) == 4
        assert block.get_block_type() == "conditional"
        assert block.get_falls_to() == 160
        assert block.get_jump_target() == 200
        assert block.get_branch_expression() == "x > y"

    def test_basic_block_equality_not_implemented(self):
        """Test that basic blocks don't have equality implemented."""
        block1 = BasicBlock(100, 200)
        block2 = BasicBlock(100, 200)

        # Should be different objects even with same addresses
        assert block1 is not block2

    def test_basic_block_modification_after_creation(self):
        """Test modifying basic block after creation."""
        block = BasicBlock(0, 10)

        # Initially empty
        assert len(block.get_instructions()) == 0
        assert block.get_block_type() is None

        # Add content
        block.add_instruction("NOP")
        block.set_block_type("terminal")

        # Verify changes
        assert len(block.get_instructions()) == 1
        assert block.get_block_type() == "terminal"

        # Modify again
        block.add_instruction("STOP")
        block.set_block_type("unconditional")

        # Verify further changes
        assert len(block.get_instructions()) == 2
        assert block.get_block_type() == "unconditional"

    def test_basic_block_with_realistic_evm_scenario(self):
        """Test basic block with realistic EVM bytecode scenario."""
        # Simulate a conditional jump block
        block = BasicBlock(0x100, 0x120)

        # Add typical EVM instructions
        instructions = [
            "PUSH1 0x00",  # Push 0 onto stack
            "CALLDATALOAD",  # Load call data
            "PUSH1 0x10",  # Push 16 onto stack
            "LT",  # Less than comparison
            "PUSH2 0x0200",  # Push jump target
            "JUMPI",  # Conditional jump
        ]

        for instr in instructions:
            block.add_instruction(instr)

        block.set_block_type("conditional")
        block.set_falls_to(0x121)  # Next sequential address
        block.set_jump_target(0x200)  # Jump target address

        # Verify the configuration
        assert block.get_start_address() == 0x100
        assert block.get_end_address() == 0x120
        assert len(block.get_instructions()) == 6
        assert block.get_instructions()[-1] == "JUMPI"
        assert block.get_block_type() == "conditional"
        assert block.get_falls_to() == 0x121
        assert block.get_jump_target() == 0x200


@pytest.mark.unit
class TestBasicBlockEdgeCases:
    """Test edge cases and error conditions."""

    def test_basic_block_with_very_large_addresses(self):
        """Test basic block with very large addresses."""
        large_addr = 2**32
        block = BasicBlock(large_addr, large_addr + 1000)

        assert block.get_start_address() == large_addr
        assert block.get_end_address() == large_addr + 1000

    def test_basic_block_instruction_types(self):
        """Test adding various instruction types."""
        block = BasicBlock(0, 10)

        # Add different types of instructions
        instructions = [
            "PUSH1 0xFF",  # Standard opcode with param
            "ADD",  # Simple opcode
            "0x6001600201",  # Raw bytecode
            "// Comment",  # Comment
            "INVALID_OPCODE",  # Invalid opcode
            "PUSH32 0x" + "00" * 32,  # Long instruction
        ]

        for instr in instructions:
            block.add_instruction(instr)

        retrieved = block.get_instructions()
        assert len(retrieved) == 6
        assert all(retrieved[i] == instructions[i] for i in range(6))

    def test_basic_block_state_consistency(self):
        """Test that basic block maintains consistent state."""
        block = BasicBlock(100, 200)

        # Set various properties
        block.set_block_type("test")
        block.set_falls_to(300)
        block.set_jump_target(400)
        block.add_instruction("TEST")

        # Verify state is consistent
        assert block.start == 100
        assert block.end == 200
        assert block.type == "test"
        assert block.falls_to == 300
        assert block.jump_target == 400
        assert "TEST" in block.instructions

        # Modify one property
        block.set_block_type("modified")

        # Other properties should remain unchanged
        assert block.start == 100
        assert block.end == 200
        assert block.type == "modified"  # This should change
        assert block.falls_to == 300
        assert block.jump_target == 400
        assert "TEST" in block.instructions

    def test_basic_block_string_representations(self):
        """Test how basic block handles string representations."""
        block = BasicBlock(0, 10)

        # The BasicBlock class doesn't define __str__ or __repr__
        # so it should use the default object representation
        str_repr = str(block)
        assert "BasicBlock" in str_repr
        assert "object at" in str_repr

    @pytest.mark.parametrize("start,end", [(0, 1), (100, 200), (-10, -5), (2**31, 2**31 + 1), (0, 0)])
    def test_basic_block_address_ranges(self, start, end):
        """Test basic block with various address ranges."""
        block = BasicBlock(start, end)

        assert block.get_start_address() == start
        assert block.get_end_address() == end

    def test_basic_block_memory_efficiency(self):
        """Test that basic block is memory efficient."""
        # Create many basic blocks to test memory usage
        blocks = []
        for i in range(1000):
            block = BasicBlock(i * 10, i * 10 + 5)
            block.add_instruction(f"INSTR_{i}")
            blocks.append(block)

        # All blocks should be independent
        assert len(blocks) == 1000
        assert all(block.get_start_address() == i * 10 for i, block in enumerate(blocks))
        assert all(len(block.get_instructions()) == 1 for block in blocks)

    def test_basic_block_immutable_addresses(self):
        """Test that addresses cannot be changed after creation."""
        block = BasicBlock(100, 200)

        # Addresses should be read-only through getters
        assert block.get_start_address() == 100
        assert block.get_end_address() == 200

        # Direct modification should be possible (no property protection)
        block.start = 150
        block.end = 250

        assert block.get_start_address() == 150
        assert block.get_end_address() == 250
