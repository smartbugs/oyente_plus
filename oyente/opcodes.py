"""EVM opcode definitions and gas cost calculations.

This module contains definitions for Ethereum Virtual Machine (EVM) opcodes,
including their hexadecimal values, stack effects, and gas costs. It provides
functions to look up opcode information and calculate instruction costs.
"""

from typing import Dict
from typing import List
from typing import Sequence
from typing import Tuple
from typing import Union


# list of all opcodes except the SWAPi, PUSHi and DUPi
# opcodes[name] has a list of [value (index), no. of items removed from stack, no. of items added to stack]
opcodes: Dict[str, List[int]] = {
    "STOP": [0x00, 0, 0],
    "ADD": [0x01, 2, 1],
    "MUL": [0x02, 2, 1],
    "SUB": [0x03, 2, 1],
    "DIV": [0x04, 2, 1],
    "SDIV": [0x05, 2, 1],
    "MOD": [0x06, 2, 1],
    "SMOD": [0x07, 2, 1],
    "ADDMOD": [0x08, 3, 1],
    "MULMOD": [0x09, 3, 1],
    "EXP": [0x0A, 2, 1],
    "SIGNEXTEND": [0x0B, 2, 1],
    "LT": [0x10, 2, 1],
    "GT": [0x11, 2, 1],
    "SLT": [0x12, 2, 1],
    "SGT": [0x13, 2, 1],
    "EQ": [0x14, 2, 1],
    "ISZERO": [0x15, 1, 1],
    "AND": [0x16, 2, 1],
    "OR": [0x17, 2, 1],
    "XOR": [0x18, 2, 1],
    "NOT": [0x19, 1, 1],
    "BYTE": [0x1A, 2, 1],
    "SHL": [0x1B, 2, 1],
    "SHR": [0x1C, 2, 1],
    "SAR": [0x1D, 2, 1],
    "SHA3": [0x20, 2, 1],
    "ADDRESS": [0x30, 0, 1],
    "BALANCE": [0x31, 1, 1],
    "ORIGIN": [0x32, 0, 1],
    "CALLER": [0x33, 0, 1],
    "CALLVALUE": [0x34, 0, 1],
    "CALLDATALOAD": [0x35, 1, 1],
    "CALLDATASIZE": [0x36, 0, 1],
    "CALLDATACOPY": [0x37, 3, 0],
    "CODESIZE": [0x38, 0, 1],
    "CODECOPY": [0x39, 3, 0],
    "GASPRICE": [0x3A, 0, 1],
    "EXTCODESIZE": [0x3B, 1, 1],
    "EXTCODECOPY": [0x3C, 4, 0],
    "RETURNDATASIZE": [0x3D, 0, 1],
    "RETURNDATACOPY": [0x3E, 3, 0],
    "EXTCODEHASH": [0x3F, 1, 1],
    "BLOCKHASH": [0x40, 1, 1],
    "COINBASE": [0x41, 0, 1],
    "TIMESTAMP": [0x42, 0, 1],
    "NUMBER": [0x43, 0, 1],
    "PREVRANDAO": [0x44, 0, 1],
    "GASLIMIT": [0x45, 0, 1],
    "CHAINID": [0x46, 0, 1],
    "SELFBALANCE": [0x47, 0, 1],
    "BASEFEE": [0x48, 0, 1],
    "BLOBHASH": [0x49, 1, 1],
    "BLOBBASEFEE": [0x4A, 0, 1],
    "POP": [0x50, 1, 0],
    "MLOAD": [0x51, 1, 1],
    "MSTORE": [0x52, 2, 0],
    "MSTORE8": [0x53, 2, 0],
    "SLOAD": [0x54, 1, 1],
    "SSTORE": [0x55, 2, 0],
    "JUMP": [0x56, 1, 0],
    "JUMPI": [0x57, 2, 0],
    "PC": [0x58, 0, 1],
    "MSIZE": [0x59, 0, 1],
    "GAS": [0x5A, 0, 1],
    "JUMPDEST": [0x5B, 0, 0],
    "TLOAD": [0x5C, 1, 1],
    "TSTORE": [0x5D, 2, 0],
    "MCOPY": [0x5E, 3, 0],
    "PUSH0": [0x5F, 0, 1],
    "LOG0": [0xA0, 2, 0],
    "LOG1": [0xA1, 3, 0],
    "LOG2": [0xA2, 4, 0],
    "LOG3": [0xA3, 5, 0],
    "LOG4": [0xA4, 6, 0],
    "CREATE": [0xF0, 3, 1],
    "CALL": [0xF1, 7, 1],
    "CALLCODE": [0xF2, 7, 1],
    "RETURN": [0xF3, 2, 0],
    "DELEGATECALL": [0xF4, 6, 1],
    "CREATE2": [0xF5, 4, 1],
    "RNGSEED": [0xF6, 1, 1],
    "SSIZEEXT": [0xF7, 2, 1],
    "SLOADBYTES": [0xF8, 3, 0],
    "SSTOREBYTES": [0xF9, 3, 0],
    "STATICCALL": [0xFA, 6, 1],
    "STATEROOT": [0xFB, 1, 1],
    "TXEXECGAS": [0xFC, 0, 1],
    "REVERT": [0xFD, 2, 0],
    "INVALID": [0xFE, 0, 0],  # Not an opcode use to cause an exception
    "ASSERTFAIL": [0xFE, 0, 0],
    "SELFDESTRUCT": [0xFF, 1, 0],
    "---END---": [0x00, 0, 0],
}

# TO BE UPDATED IF ETHEREUM VM CHANGES their fee structure

GCOST: Dict[str, int] = {
    "Gzero": 0,
    "Gbase": 2,
    "Gverylow": 3,
    "Glow": 5,
    "Gmid": 8,
    "Ghigh": 10,
    "Gextcode": 20,
    "Gextcodehash": 700,
    "Gbalance": 700,
    "Gsload": 2100,
    "Gjumpdest": 1,
    "Gsset": 20000,
    "Gsreset": 5000,
    "Rsclear": 15000,
    "Rsuicide": 0,
    "Gsuicide": 5000,
    "Gcreate": 32000,
    "Gcodedeposit": 200,
    "Gcall": 700,
    "Gcallvalue": 9000,
    "Gcallstipend": 2300,
    "Gnewaccount": 25000,
    "Gexp": 10,
    "Gexpbyte": 10,
    "Gmemory": 3,
    "Gtxcreate": 32000,
    "Gtxdatazero": 4,
    "Gtxdatanonzero": 68,
    "Gtransaction": 21000,
    "Glog": 375,
    "Glogdata": 8,
    "Glogtopic": 375,
    "Gsha3": 30,
    "Gsha3word": 6,
    "Gcopy": 3,
    "Gblockhash": 20,
    "GTransientStorage": 100,
}

INSTRUCTIONS: List[str] = [
    "STOP",
    "ADD",
    "MUL",
    "SUB",
    "DIV",
    "SDIV",
    "MOD",
    "SMOD",  # 0x00-0x07
    "ADDMOD",
    "MULMOD",
    "EXP",
    "SIGNEXTEND",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0x08-0x0F
    "LT",
    "GT",
    "SLT",
    "SGT",
    "EQ",
    "ISZERO",
    "AND",
    "OR",  # 0x10-0x17
    "XOR",
    "NOT",
    "BYTE",
    "SHL",
    "SHR",
    "SAR",
    "INVALID",
    "INVALID",  # 0x18-0x1F
    "KECCAK256",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0x20-0x27
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0x28-0x2f
    "ADDRESS",
    "BALANCE",
    "ORIGIN",
    "CALLER",
    "CALLVALUE",
    "CALLDATALOAD",
    "CALLDATASIZE",
    "CALLDATACOPY",  # 0x30-0x37
    "CODESIZE",
    "CODECOPY",
    "GASPRICE",
    "EXTCODESIZE",
    "EXTCODECOPY",
    "RETURNDATASIZE",
    "RETURNDATACOPY",
    "EXTCODEHASH",  # 0x38-0x3F
    "BLOCKHASH",
    "COINBASE",
    "TIMESTAMP",
    "NUMBER",
    "PREVRANDAO",
    "GASLIMIT",
    "CHAINID",
    "SELFBALANCE",  # 0x40-0x47
    "BASEFEE",
    "BLOBHASH",
    "BLOBBASEFEE",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0x48-0x4F
    "POP",
    "MLOAD",
    "MSTORE",
    "MSTORE8",
    "SLOAD",
    "SSTORE",
    "JUMP",
    "JUMPI",  # 0x50-0x57
    "PC",
    "MSIZE",
    "GAS",
    "JUMPDEST",
    "TLOAD",
    "TSTORE",
    "MCOPY",
    "PUSH0",  # 0x58-0x5F
    "PUSH1",
    "PUSH2",
    "PUSH3",
    "PUSH4",
    "PUSH5",
    "PUSH6",
    "PUSH7",
    "PUSH8",  # 0x60-0x67
    "PUSH9",
    "PUSH10",
    "PUSH11",
    "PUSH12",
    "PUSH13",
    "PUSH14",
    "PUSH15",
    "PUSH16",  # 0x68-0x6F
    "PUSH17",
    "PUSH18",
    "PUSH19",
    "PUSH20",
    "PUSH21",
    "PUSH22",
    "PUSH23",
    "PUSH24",  # 0x70-0x77
    "PUSH25",
    "PUSH26",
    "PUSH27",
    "PUSH28",
    "PUSH29",
    "PUSH30",
    "PUSH31",
    "PUSH32",  # 0x78-0x7F
    "DUP1",
    "DUP2",
    "DUP3",
    "DUP4",
    "DUP5",
    "DUP6",
    "DUP7",
    "DUP8",  # 0x80-0x87
    "DUP9",
    "DUP10",
    "DUP11",
    "DUP12",
    "DUP13",
    "DUP14",
    "DUP15",
    "DUP16",  # 0x88-0x8F
    "SWAP1",
    "SWAP2",
    "SWAP3",
    "SWAP4",
    "SWAP5",
    "SWAP6",
    "SWAP7",
    "SWAP8",  # 0x90-0x97
    "SWAP9",
    "SWAP10",
    "SWAP11",
    "SWAP12",
    "SWAP13",
    "SWAP14",
    "SWAP15",
    "SWAP16",  # 0x98-0x9F
    "LOG0",
    "LOG1",
    "LOG2",
    "LOG3",
    "LOG4",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xA0-0xA7
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xA8-0xAF
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xB0-0xB7
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xB8-0xBF
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xC0-0xC7
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xC8-0xCF
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xD0-0xD7
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xD8-0xDF
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xE0-0xE7
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",
    "INVALID",  # 0xE8-0xEF
    "CREATE",
    "CALL",
    "CALLCODE",
    "RETURN",
    "DELEGATECALL",
    "CREATE2",
    "INVALID",
    "INVALID",  # 0xF0-0xF7
    "INVALID",
    "INVALID",
    "STATICCALL",
    "INVALID",
    "INVALID",
    "REVERT",
    "INVALID",
    "SELFDESTRUCT",  # 0xF8-0xFF
]

Wzero: Tuple[str, ...] = ("STOP", "RETURN", "REVERT", "ASSERTFAIL")

Wbase: Tuple[str, ...] = (
    "ADDRESS",
    "ORIGIN",
    "CALLER",
    "CALLVALUE",
    "CALLDATASIZE",
    "CODESIZE",
    "GASPRICE",
    "COINBASE",
    "TIMESTAMP",
    "NUMBER",
    "PREVRANDAO",
    "GASLIMIT",
    "POP",
    "PC",
    "MSIZE",
    "GAS",
    "BLOBHASH",
    "PUSH0",
)

Wverylow: Tuple[str, ...] = (
    "ADD",
    "SUB",
    "NOT",
    "LT",
    "GT",
    "SLT",
    "SHL",
    "SHR",
    "SAR",
    "SGT",
    "EQ",
    "ISZERO",
    "AND",
    "OR",
    "XOR",
    "BYTE",
    "CALLDATALOAD",
    "MLOAD",
    "MSTORE",
    "MSTORE8",
    "PUSH",
    "DUP",
    "SWAP",
    "BLOBBASEFEE",
)

Wlow: Tuple[str, ...] = ("MUL", "DIV", "SDIV", "MOD", "SMOD", "SIGNEXTEND")

Wmid: Tuple[str, ...] = ("ADDMOD", "MULMOD", "JUMP")

Whigh: str = "JUMPI"

Wext: str = "EXTCODESIZE"

Wtransientstorage: Tuple[str, ...] = ("TLOAD", "TSTORE")


def get_opcode(opcode: str) -> Sequence[Union[str, int]]:
    """Get opcode information including hex value and stack effects.

    Args:
        opcode: The opcode name (e.g., 'ADD', 'PUSH1', 'DUP3')

    Returns:
        A sequence containing:
        - [0]: Hexadecimal value of the opcode (string or int)
        - [1]: Number of items removed from stack
        - [2]: Number of items added to stack

    Raises:
        ValueError: If the opcode is not recognized

    Example:
        >>> get_opcode('ADD')
        [0x01, 2, 1]  # Takes 2 items, pushes 1 result
    """
    if opcode in opcodes:
        return opcodes[opcode]
    # check PUSHi
    for i in range(32):
        if opcode == "PUSH" + str(i + 1):
            return [hex(0x60 + i), 0, 1]

    # check DUPi
    for i in range(16):
        if opcode == "DUP" + str(i + 1):
            return [hex(0x80 + i), i + 1, i + 2]

    # check SWAPi
    for i in range(16):
        if opcode == "SWAP" + str(i + 1):
            return [hex(0x90 + i), i + 2, i + 2]
    raise ValueError("Bad Opcode: " + opcode)


def get_ins_cost(opcode: str) -> int:
    """Calculate the gas cost for a given opcode.

    This function returns the base gas cost for executing an opcode,
    not including any dynamic costs that depend on operand values.

    Args:
        opcode: The opcode name (e.g., 'ADD', 'SSTORE')

    Returns:
        The gas cost in units, or 0 if the opcode is not recognized

    Example:
        >>> get_ins_cost('ADD')
        3  # Gverylow cost
        >>> get_ins_cost('SSTORE')
        20000  # Gsset cost (simplified, actual cost is more complex)

    Note:
        This returns the base cost only. Many operations have additional
        dynamic costs based on their operands (e.g., memory expansion,
        storage changes, etc.) which are not included here.
    """
    if opcode in Wzero:
        return GCOST["Gzero"]
    elif opcode in Wbase:
        return GCOST["Gbase"]
    elif opcode in Wverylow or opcode.startswith("PUSH") or opcode.startswith("DUP") or opcode.startswith("SWAP"):
        return GCOST["Gverylow"]
    elif opcode in Wlow:
        return GCOST["Glow"]
    elif opcode in Wmid:
        return GCOST["Gmid"]
    elif opcode in Whigh:
        return GCOST["Ghigh"]
    elif opcode in Wext:
        return GCOST["Gextcode"]
    elif opcode == "EXTCODEHASH":
        return GCOST["Gextcodehash"]
    elif opcode == "EXP":
        return GCOST["Gexp"]
    elif opcode == "SLOAD":
        return GCOST["Gsload"]
    elif opcode == "JUMPDEST":
        return GCOST["Gjumpdest"]
    elif opcode == "SHA3":
        return GCOST["Gsha3"]
    elif opcode in ("CREATE", "CREATE2"):
        return GCOST["Gcreate"]
    elif opcode in ("CALL", "CALLCODE", "STATICCALL"):
        return GCOST["Gcall"]
    elif opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
        num_topics = int(opcode[3:])
        return GCOST["Glog"] + num_topics * GCOST["Glogtopic"]
    elif opcode == "EXTCODECOPY":
        return GCOST["Gextcode"]
    elif opcode in ("CALLDATACOPY", "CODECOPY"):
        return GCOST["Gverylow"]
    elif opcode == "BALANCE":
        return GCOST["Gbalance"]
    elif opcode == "BLOCKHASH":
        return GCOST["Gblockhash"]
    elif opcode in Wtransientstorage:
        return GCOST["GTransientStorage"]
    elif opcode == "MCOPY":
        return GCOST["Gcopy"]
    return 0
