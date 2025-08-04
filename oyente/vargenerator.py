"""Variable name generator for symbolic execution.

This module provides a Generator class that creates unique variable names
for different types of symbolic variables used during EVM bytecode analysis.
"""

from typing import Union


class Generator:
    """Generate unique variable names for symbolic execution.

    This class maintains counters for different variable types and generates
    unique names for stack variables, data variables, memory variables, and
    other symbolic values used during EVM bytecode analysis.

    Attributes:
        countstack: Counter for stack variables
        countdata: Counter for data variables
        count: General counter for arbitrary variables
    """

    def __init__(self) -> None:
        """Initialize the variable generator with zero counters."""
        self.countstack = 0
        self.countdata = 0
        self.count = 0

    def gen_stack_var(self) -> str:
        """Generate a unique stack variable name.

        Returns:
            A string in the format "s<number>" where number is incremented
            for each call.
        """
        self.countstack += 1
        return "s" + str(self.countstack)

    def gen_data_var(self, position: Union[int, str, None] = None) -> str:
        """Generate a unique data variable name.

        Args:
            position: Optional position parameter (currently unused)

        Returns:
            A string in the format "Id_<number>" where number is incremented
            for each call.
        """
        self.countdata += 1
        return "Id_" + str(self.countdata)

    def gen_data_size(self) -> str:
        """Generate a data size variable name.

        Returns:
            The constant string "Id_size".
        """
        return "Id_size"

    def gen_mem_var(self, address: Union[int, str]) -> str:
        """Generate a memory variable name for a specific address.

        Args:
            address: The memory address (can be int or string)

        Returns:
            A string in the format "mem_<address>".
        """
        return "mem_" + str(address)

    def gen_arbitrary_var(self) -> str:
        """Generate a unique arbitrary variable name.

        Returns:
            A string in the format "some_var_<number>" where number is
            incremented for each call.
        """
        self.count += 1
        return "some_var_" + str(self.count)

    def gen_arbitrary_address_var(self) -> str:
        """Generate a unique arbitrary address variable name.

        Returns:
            A string in the format "some_address_<number>" where number is
            incremented for each call.
        """
        self.count += 1
        return "some_address_" + str(self.count)

    def gen_owner_store_var(self, position: Union[int, str], var_name: str = "") -> str:
        """Generate an owner storage variable name.

        Args:
            position: The storage position
            var_name: Optional variable name suffix

        Returns:
            A string in the format "Ia_store-<position>-<var_name>".
        """
        return f"Ia_store-{position!s}-{var_name}"

    def gen_gas_var(self) -> str:
        """Generate a unique gas variable name.

        Returns:
            A string in the format "gas_<number>" where number is incremented
            for each call.
        """
        self.count += 1
        return "gas_" + str(self.count)

    def gen_gas_price_var(self) -> str:
        """Generate a gas price variable name.

        Returns:
            The constant string "Ip".
        """
        return "Ip"

    def gen_address_var(self) -> str:
        """Generate an address variable name.

        Returns:
            The constant string "Ia".
        """
        return "Ia"

    def gen_caller_var(self) -> str:
        """Generate a caller variable name.

        Returns:
            The constant string "Is".
        """
        return "Is"

    def gen_origin_var(self) -> str:
        """Generate an origin variable name.

        Returns:
            The constant string "Io".
        """
        return "Io"

    def gen_balance_var(self) -> str:
        """Generate a unique balance variable name.

        Returns:
            A string in the format "balance_<number>" where number is
            incremented for each call.
        """
        self.count += 1
        return "balance_" + str(self.count)

    def gen_code_var(self, address: Union[int, str], position: Union[int, str], bytecount: Union[int, str]) -> str:
        """Generate a code variable name.

        Args:
            address: The code address
            position: The position in the code
            bytecount: The number of bytes

        Returns:
            A string in the format "code_<address>_<position>_<bytecount>".
        """
        return "code_" + str(address) + "_" + str(position) + "_" + str(bytecount)

    def gen_code_size_var(self, address: Union[int, str]) -> str:
        """Generate a code size variable name.

        Args:
            address: The code address

        Returns:
            A string in the format "code_size_<address>".
        """
        return "code_size_" + str(address)
