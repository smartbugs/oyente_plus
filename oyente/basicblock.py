"""Basic block representation for control flow graph analysis.

This module provides the BasicBlock class that represents a basic block
in the control flow graph of EVM bytecode during analysis.
"""

from typing import Any
from typing import Optional
from typing import Union


class BasicBlock:
    """Represents a basic block in the control flow graph.

    A basic block is a sequence of instructions with a single entry point
    and a single exit point. It's used to build the control flow graph
    during EVM bytecode analysis.

    Attributes:
        start: The starting address of the block
        end: The ending address of the block
        instructions: List of instructions in the block
        type: The type of block (e.g., 'conditional', 'unconditional')
        falls_to: Address of the next block in sequential execution
        jump_target: Target address for jump instructions
        branch_expression: The condition expression for conditional jumps
    """

    def __init__(self, start_address: int, end_address: int) -> None:
        """Initialize a basic block with start and end addresses.

        Args:
            start_address: The starting address of the block
            end_address: The ending address of the block
        """
        self.start = start_address
        self.end = end_address
        self.instructions: list[str] = []  # each instruction is a string
        self.jump_target: int = 0
        self.type: Optional[str] = None
        self.falls_to: Optional[int] = None
        self.branch_expression: Optional[Any] = None

    def get_start_address(self) -> int:
        """Get the starting address of the block.

        Returns:
            The starting address as an integer.
        """
        return self.start

    def get_end_address(self) -> int:
        """Get the ending address of the block.

        Returns:
            The ending address as an integer.
        """
        return self.end

    def add_instruction(self, instruction: str) -> None:
        """Add an instruction to the block.

        Args:
            instruction: The instruction string to add.
        """
        self.instructions.append(instruction)

    def get_instructions(self) -> list[str]:
        """Get all instructions in the block.

        Returns:
            List of instruction strings.
        """
        return self.instructions

    def set_block_type(self, type: str) -> None:
        """Set the type of the block.

        Args:
            type: The block type (e.g., 'conditional', 'unconditional').
        """
        self.type = type

    def get_block_type(self) -> Optional[str]:
        """Get the type of the block.

        Returns:
            The block type or None if not set.
        """
        return self.type

    def set_falls_to(self, address: int) -> None:
        """Set the address of the next block in sequential execution.

        Args:
            address: The address the block falls to.
        """
        self.falls_to = address

    def get_falls_to(self) -> Optional[int]:
        """Get the address of the next block in sequential execution.

        Returns:
            The address the block falls to or None if not set.
        """
        return self.falls_to

    def set_jump_target(self, address: Union[int, Any]) -> None:
        """Set the jump target address.

        Args:
            address: The target address for jump instructions.
                    If not an integer, sets jump_target to -1.
        """
        if isinstance(address, int):
            self.jump_target = address
        else:
            self.jump_target = -1

    def get_jump_target(self) -> int:
        """Get the jump target address.

        Returns:
            The jump target address or -1 if invalid.
        """
        return self.jump_target

    def set_branch_expression(self, branch: Any) -> None:
        """Set the branch condition expression.

        Args:
            branch: The condition expression for conditional jumps.
        """
        self.branch_expression = branch

    def get_branch_expression(self) -> Optional[Any]:
        """Get the branch condition expression.

        Returns:
            The branch expression or None if not set.
        """
        return self.branch_expression

    def display(self) -> None:
        """Display the basic block information.

        Prints the block's start/end addresses, type, and instructions
        to standard output for debugging purposes.
        """
        print("================")
        print(f"start address: {self.start}")
        print(f"end address: {self.end}")
        if self.type:
            print(f"end statement type: {self.type}")
        for instr in self.instructions:
            print(instr)
