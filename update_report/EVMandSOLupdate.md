# Update EVM & Solidity support

Oyente was one of the first tools for detecting vulnerabilities in Ethereum smart contracts. It has frequently served in comparisons with newer tools. For some time, Oyente was maintained by the community, but by now has been archived at [github.com/enzymefinance/oyente](https://github.com/enzymefinance/oyente). The version there is outdated and no longer able to analyze recent contracts.

The version of Oyente here, Oyente+, has been updated to support the newest EVM and Solidity versions. The major changes are the following ones.

  - [Disassembler](#disassembler)
    - [pyevmasm](#pyevmasm)
    - [evmdasm](#evmdasm)
    - [geas](#geas)
  - [Opcodes](#opcodes)
  - [Solidity](#solidity)
    - [New Abstract Syntax Tree (AST) format](#new-abstract-syntax-tree-ast-format)
    - [Source Map](#source-map)
    - [Contract Metadata](#contract-metadata)
  - [Dockerfile](#dockerfile)
  - [Dependencies](#dependencies)
  - [Unittests](#unittests)

## Disassembler

Oyente disassembles bytecode to mnemonic instructions.
The original version used `evmasm`, a disassambler shipped with EVM `1.7.3`, but not with recent versions like `1.15.11`. As a replacement, Oyente+ offers three alternatives, selected by the commandline option `-d` followed by one of the values `evmdasm` (default), `pyevmasm`, and `geas`.

The function `_write_disasm_file` in `input_helper.py` transforms the output of the selected disassembler to the format expected by Oyente, where each line consists of an address (5 hex digits), an opcode and stack values.

```bytecode
00001: TSTORE 0x0 0x1234
00002: PUSH0
...
```

### evmdasm

`evmdasm` is the disassembler used by default. It is Python-based and installed automatically by `setup-venv.py`. It has not been updated for some years. As it represents new operations as `UNKNOWN_0x..`, `_write_disasm_file` can replace them by the appropriate mnemonics.

### pyevmasm

`pyevmasm` does not generate addresses, which therefore have to be added by `_write_disasm_file`. Unknown operations are represented just as `UNKNOWN` and cannot be reconstructed. In such a case, Oyente+ stops its program analysis, yielding reduced code coverage.


### geas

`geas` writes invalid opcodes as `#bytes 0x....`, which is mapped to a format suitable for Oyente. `geas` is the newest disassembler in the mix and supports all current opcodes. As it is based on GO, it is not set as default.

## Opcodes

Oyente+ updates `opcodes.py` and `symExec.py` to handle new opcodes.

- Operations added with their gas costs, global state variables and symbolic effects:
  - `CHAINID`
  - `BASEFEE`
  - `BLOBHASH`
  - `BLOBBASEFEE`
  - `SELFBALANCE`
  - `MCOPY` (minimal implementation of the stack effects)
  - `PUSH0` (implemented as a special case of the general PUSH)
  - `TLOAD` (loads from a global_state variable `It`, which does not get reset after a block was processed)
  - `TSTORE` (writes to a global_state variable `It`, which does not get reset after a block was processed)
- Operations renamed:
  - `SUICIDE` to `SELFDESTRUCT`
  - `DIFFICULTY` to `PREVRANDAO`
  - `CALLSTATIC` to `REVERT`
  - `BREAKPOINT` to `CREATE2`
- Operations removed:
  - `SLOADEXT`
  - `SSTOREEXT`
  - `SLOADBYTESEXT`
  - `SSTOREBYTESEXT`

For debugging purposes, Oyente+ logs the construction of vertices, edges and jump_types. Moreover, it logs the execution of new, complex opcodes (like `MCOPY`, `TLOAD`, `TSTORE`) to faciliate more precise modelling later on.
At the moment, such operations are implemented in a minimal form to allow for the analysis to continue beyond the point.

## Solidity

### New Abstract Syntax Tree (AST) format

Oyente's symbolic executor walks the AST looking for `ContractDefinition`, `VariableDeclaration`, `FunctionCall`, etc., expecting the v4 format (`node["name"]`, `node["children"]`, `node["attributes"]["..."]`). Since Solidity version `0.5.0`, the AST format has become nested, therefore the original Oyente cannot correctly analyze smart contracts written in new Solidity versions.

Oyente+ semi-converts the v5+ format (Solidity version ≥ `0.5.0+`) to the v4 format (Solidity version < `0.5.0+`), to avoid the rewriting of the entire symExec codebase. If newer Solidity versions introduce further AST changes, this conversion can be extended.

The following table shows relevant differences between the old and the new format:

| Aspect                     | v4 format                                           | v5+ format                                                                                   |
|----------------------------|------------------------------------------------------|----------------------------------------------------------------------------------------------|
| **Root AST container**     | A flat JSON with `"AST"` at each source, listing a tree of nodes with keys: `name`, `attributes`, `children`, `id`, `src`. | A nested JSON where each node has `"nodeType"` and a `"nodes"` array; other fields (e.g. `parameters`, `returnParameters`, `body`) may also embed AST dicts inline. |
| **Node identity**          | Field `name` holds the node’s type (e.g. `"FunctionDefinition"`). | Field `nodeType` holds the node’s type; `name` may appear inside `attributes`.               |
| **Child nodes**            | Always under a `children` array, in the exact original Etherscan order. | Primarily under `nodes`, but may also appear inline under other keys (`parameters`, `body`, etc.). |
| **Attributes**             | Under an `attributes` object, containing only the data needed by symExec. | Spread across many fields: `typeDescriptions`, `stateMutability`, `mutability`, `nameLocation`, and so on. |
| **Type information**       | Synthesized into `attributes.type` by the compiler. | Encoded under `typeDescriptions.typeString` on type‐nodes (e.g. `ElementaryTypeName`).        |
| **Other metadata**         | No `typeDescriptions`, no `nodeType`, no inline mutability fields. | Richer metadata (`typeDescriptions`, `documentation`, `stateMutability`, etc.) that v4 code doesn’t understand. |

### Source Map

New EVM versions introduce new names for existing opcodes and add new ones. To fix related issues in the `mapping_non_push_instructions` function, we create a mapping for aliases of opcodes and use this mapping to check if the instruction name matches the source map name. This alias map is currently held locally in the function, but may be moved to a global place like `opcodes.py`. New aliases can be added for supporting further changes of the EVM opcodes in the future.

To support the new `PUSH0` instruction, we patch the function `mapping_push_instruction`. In Solidity versions ≥ `0.6.0`, the `"name":"PUSH"` entries in the source map always designates zero-byte pushes. Numbered pushes keep their `"name":"PUSHn"`  *without* a matching `value` field.

### Contract Metadata

For a static analysis, we do not need the [Contract metadata](https://docs.soliditylang.org/en/latest/metadata.html) or the [NatSpec Format](https://docs.soliditylang.org/en/latest/natspec-format.html) data. The Solidity compiler adds a **CBOR-encoded map** followed by its **two byte big-endian length**:

```json
{
  "ipfs": "<metadata hash>",
  // If "bytecodeHash" was "bzzr1" in compiler settings not "ipfs" but "bzzr1"
  "bzzr1": "<metadata hash>",
  // Previous versions were using "bzzr0" instead of "bzzr1"
  "bzzr0": "<metadata hash>",
  // If any experimental features that affect code generation are used
  "experimental": true,
  "solc": "<compiler version>"
}
```

It may include more fields in the future. We remove this metadata from the bytecode, using the [ethutils](https://github.com/gsalzer/ethutils) repository to zero all metadata still left in the contract, so Oyente+ analyzes clean bytecode.

## Dockerfile

The Dockerfile for Oyente has been completely reworked. All Dockerfile linter warnings were fixed and the dependencies and statements were cleaned. The base image is now `ubuntu:jammy`. Since `solc-select` does not work inside the container, the solidity version which is to be used, has to be set in the Dockerfile via `ARG SOLC_VERSION=x.x.x`. The version then gets installed automatically and the respective environment variable, which is used by solc, is set.

To be able to use the disassembler `geas`, we had to install go as a dependency.

## Dependencies

The dependencies were reviewed and we added the new disassemblers `evmdasm` and `pyevmasm` to the list. We also had some updates done:

- `crytic-compile` was updated to version `0.3.8`, which solved some minor issues with `solc` and `solc-select`
- `z3-solver` was updated to version `4.14.1.0`, which significantly improved performance of symbolic execution and fixed some minor issues as well

For removing the cbor metadata, we installed `cbor2` as a dependency.

## Unittests

Oyente has a set of unittests to test the EVM and some of the opcodes. This is done with `run_tests.py` which relys on test data stored in `test_evm/test_data` in json format. To add new tests, simply add new files with tests using the current format (or add the tests to the current files). Before our update `run_tests.py` and `test_evm/*.py` were written in `python2`, and are now updated to `python3`. During the upgrade some minor improvements were made to `test_evm/evm_unit_test.py` - now the subprocess library is used to run Oyente against the testfiles instead of the `os.system` function.
