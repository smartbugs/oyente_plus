# list of all opcodes except the SWAPi, PUSHi and DUPi
# opcodes[name] has a list of [value (index), no. of items removed from stack, no. of items added to stack]
opcodes = {
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
    "EXP": [0x0a, 2, 1],
    "SIGNEXTEND": [0x0b, 2, 1],
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
    "BYTE": [0x1a, 2, 1],
    "SHL": [0x1b, 2, 1],
    "SHR": [0x1c, 2, 1],
    "SAR": [0x1d, 2, 1],
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
    "GASPRICE": [0x3a, 0, 1],
    "EXTCODESIZE": [0x3b, 1, 1],
    "EXTCODECOPY": [0x3c, 4, 0],
    "RETURNDATASIZE": [0x3d, 0, 1],
    "RETURNDATACOPY": [0x3e, 3, 0],
    "EXTCODEHASH": [0x3f, 1, 1],
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
    "BLOBBASEFEE": [0x4a, 0, 1],
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
    "GAS": [0x5a, 0, 1],
    "JUMPDEST": [0x5b, 0, 0],
    "TLOAD": [0x5c, 1, 1],
    "TSTORE": [0x5d, 2, 0],
    "MCOPY": [0x5e, 3, 0],
    "PUSH0": [0x5f, 0, 1],
    "LOG0": [0xa0, 2, 0],
    "LOG1": [0xa1, 3, 0],
    "LOG2": [0xa2, 4, 0],
    "LOG3": [0xa3, 5, 0],
    "LOG4": [0xa4, 6, 0],
    "CREATE": [0xf0, 3, 1],
    "CALL": [0xf1, 7, 1],
    "CALLCODE": [0xf2, 7, 1],
    "RETURN": [0xf3, 2, 0],
    "DELEGATECALL": [0xf4, 6, 1],
    "CREATE2": [0xf5, 4, 1],
    "RNGSEED": [0xf6, 1, 1],
    "SSIZEEXT": [0xf7, 2, 1],
    "SLOADBYTES": [0xf8, 3, 0],
    "SSTOREBYTES": [0xf9, 3, 0],
    "STATICCALL": [0xfa, 6, 1],
    "STATEROOT": [0xfb, 1, 1],
    "TXEXECGAS": [0xfc, 0, 1],
    "REVERT": [0xfd, 2, 0],
    "INVALID": [0xfe, 0, 0],  # Not an opcode use to cause an exception
    "ASSERTFAIL": [0xfe, 0, 0],
    "SELFDESTRUCT": [0xff, 1, 0],
    "---END---": [0x00, 0, 0]
}

# TO BE UPDATED IF ETHEREUM VM CHANGES their fee structure

GCOST = {
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
    "GTransientStorage": 100
}

Wzero = ("STOP", "RETURN", "REVERT", "ASSERTFAIL")

Wbase = ("ADDRESS", "ORIGIN", "CALLER", "CALLVALUE", "CALLDATASIZE",
         "CODESIZE", "GASPRICE", "COINBASE", "TIMESTAMP", "NUMBER",
         "PREVRANDAO", "GASLIMIT", "POP", "PC", "MSIZE", "GAS", "BLOBHASH",
         "PUSH0")

Wverylow = ("ADD", "SUB", "NOT", "LT", "GT", "SLT", "SHL", "SHR", "SAR",
            "SGT", "EQ", "ISZERO", "AND", "OR", "XOR", "BYTE", "CALLDATALOAD",
            "MLOAD", "MSTORE", "MSTORE8", "PUSH", "DUP", "SWAP", "BLOBBASEFEE")

Wlow = ("MUL", "DIV", "SDIV", "MOD", "SMOD", "SIGNEXTEND")

Wmid = ("ADDMOD", "MULMOD", "JUMP")

Whigh = ("JUMPI")

Wext = ("EXTCODESIZE")

Wtransientstorage = ("TLOAD", "TSTORE")

def get_opcode(opcode):
    if opcode in opcodes:
        return opcodes[opcode]
    # check PUSHi
    for i in range(32):
        if opcode == 'PUSH' + str(i + 1):
            return [hex(0x60 + i), 0, 1]

    # check DUPi
    for i in range(16):
        if opcode == 'DUP' + str(i + 1):
            return [hex(0x80 + i), i + 1, i + 2]

    # check SWAPi
    for i in range(16):
        if opcode == 'SWAP' + str(i + 1):
            return [hex(0x90 + i), i + 2, i + 2]
    raise ValueError('Bad Opcode' + opcode)


def get_ins_cost(opcode):
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
    elif opcode == ["TLOAD", "TSTORE"]:
        return GCOST["GTransientStorage"]
    elif opcode == ["MCOPY"]:
        return GCOST["Gcopy"]
    return 0
