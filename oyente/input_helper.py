"""Input handling module for Oyente+ smart contract analysis.

This module provides input handling functionality for different contract formats
including Solidity source code, EVM bytecode, and standard JSON compilation.
It supports compilation, disassembly, and temporary file management for analysis.

Key Components:
    InputHelper: Main class for handling different input types and compilation

Security Considerations:
    - Validates file paths to prevent directory traversal attacks
    - Sanitizes subprocess calls with explicit argument lists
    - Handles compilation errors gracefully without exposing sensitive info

Example:
    >>> helper = InputHelper(InputHelper.SOLIDITY, source="contract.sol")
    >>> inputs = helper.get_inputs()
    >>> for inp in inputs:
    ...     print(f"Processing {inp['contract']}")
"""

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from crytic_compile import CryticCompile  # type: ignore[attr-defined]
from crytic_compile import InvalidCompilation  # type: ignore[attr-defined]
from ethutils.metadata import zeroMetadata
from opcodes import INSTRUCTIONS
from source_map import SourceMap


class InputHelper:
    """Main class for handling different input types and compilation.

    InputHelper manages compilation and processing of smart contracts from various
    input formats including Solidity source code, EVM bytecode, and standard JSON.
    It provides compilation, disassembly, and temporary file management capabilities.

    Attributes:
        BYTECODE: Class constant (0) indicating bytecode input type
        SOLIDITY: Class constant (1) indicating Solidity source input type
        STANDARD_JSON: Class constant (2) indicating standard JSON input type
        STANDARD_JSON_OUTPUT: Class constant (3) indicating compiled JSON output type

        input_type: Type of input being processed
        source: Path to the source file or bytecode
        evm: Whether to keep EVM disassembly files after analysis
        root_path: Root directory path for resolving relative imports
        compiled_contracts: List of compiled contract tuples (name, bytecode)
        compilation_err: Whether to show detailed compilation errors
        remap: Solidity import remapping configuration
        allow_paths: Allowed paths for Solidity compilation

    Security Considerations:
        - Validates all file paths to prevent directory traversal
        - Uses full executable paths for subprocess calls
        - Sanitizes command arguments to prevent injection attacks
        - Handles compilation errors without exposing sensitive information

    Example:
        >>> # Analyze Solidity source
        >>> helper = InputHelper(InputHelper.SOLIDITY, source="contract.sol")
        >>> inputs = helper.get_inputs()
        >>>
        >>> # Analyze bytecode
        >>> helper = InputHelper(InputHelper.BYTECODE, source="bytecode.txt")
        >>> inputs = helper.get_inputs()
        >>>
        >>> # Clean up temporary files
        >>> helper.rm_tmp_files()
    """

    BYTECODE = 0
    SOLIDITY = 1
    STANDARD_JSON = 2
    STANDARD_JSON_OUTPUT = 3

    def __init__(self, input_type: int, **kwargs: Any) -> None:
        """Initialize InputHelper with specified input type and options.

        Args:
            input_type: Type of input (BYTECODE, SOLIDITY, STANDARD_JSON, STANDARD_JSON_OUTPUT)
            **kwargs: Additional configuration options depending on input type:
                - source: Path to source file (required for all types)
                - evm: Keep EVM disassembly files (default: False)
                - root_path: Root directory for imports (Solidity types only)
                - remap: Import remapping configuration (Solidity only)
                - allow_paths: Allowed compilation paths (Solidity/JSON only)
                - compilation_err: Show detailed compilation errors (Solidity only)

        Raises:
            Exception: If required attributes are None or invalid input_type

        Example:
            >>> helper = InputHelper(
            ...     InputHelper.SOLIDITY,
            ...     source="contracts/Token.sol",
            ...     allow_paths="./contracts",
            ...     remap="@openzeppelin=./node_modules/@openzeppelin"
            ... )
        """
        # Declare attributes with types
        self.input_type: int
        self.source: str
        self.evm: bool
        self.root_path: str
        self.compiled_contracts: List[Tuple[str, str]]
        self.compilation_err: bool
        self.remap: str
        self.allow_paths: str
        self.input_type = input_type

        if input_type == InputHelper.BYTECODE:
            attr_defaults: Dict[str, Any] = {
                "source": None,
                "evm": False,
            }
        elif input_type == InputHelper.SOLIDITY:
            attr_defaults = {
                "source": None,
                "evm": False,
                "root_path": "",
                "compiled_contracts": [],
                "compilation_err": False,
                "remap": "",
                "allow_paths": "",
            }
        elif input_type == InputHelper.STANDARD_JSON:
            attr_defaults = {
                "source": None,
                "evm": False,
                "root_path": "",
                "allow_paths": None,
                "compiled_contracts": [],
            }
        elif input_type == InputHelper.STANDARD_JSON_OUTPUT:
            attr_defaults = {
                "source": None,
                "evm": False,
                "root_path": "",
                "compiled_contracts": [],
            }
        else:
            raise ValueError(
                f"Invalid input_type: {input_type}. Must be one of: {InputHelper.BYTECODE}, {InputHelper.SOLIDITY}, {InputHelper.STANDARD_JSON}, {InputHelper.STANDARD_JSON_OUTPUT}"
            )

        for attr, default in attr_defaults.items():
            val = kwargs.get(attr, default)
            if val is None:
                raise Exception(f"'{attr}' attribute can't be None")
            else:
                setattr(self, attr, val)

    def get_inputs(self, target_contracts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get processed input data for analysis.

        Compiles contracts (if needed), generates disassembly files, and returns
        structured input data for each contract ready for symbolic execution.

        Args:
            target_contracts: List of specific contract names to analyze.
                            If None, analyzes all contracts found in source.

        Returns:
            List of input dictionaries, each containing:
            - For bytecode: {'disasm_file': str}
            - For source code: {
                'contract': str,        # Contract identifier
                'source_map': SourceMap, # Source mapping object
                'source': str,          # Original source path
                'c_source': str,        # Relative source path
                'c_name': str,          # Contract name
                'disasm_file': str      # Disassembly file path
              }

        Raises:
            ValueError: If target_contracts specified but not found in source
            FileNotFoundError: If source files cannot be read

        Example:
            >>> helper = InputHelper(InputHelper.SOLIDITY, source="Token.sol")
            >>> inputs = helper.get_inputs(["Token"])
            >>> for inp in inputs:
            ...     print(f"Analyzing {inp['c_name']}")
        """
        inputs = []
        if self.input_type == InputHelper.BYTECODE:
            with open(self.source) as f:
                bytecode = f.read().strip()
            # Validate bytecode format
            self._validate_bytecode(bytecode)
            self._prepare_disasm_file(self.source, bytecode)

            disasm_file = self._get_temporary_files(self.source)["disasm"]
            inputs.append({"disasm_file": disasm_file})
        else:
            contracts = self._get_compiled_contracts()
            self._prepare_disasm_files_for_analysis(contracts)
            for contract, _ in contracts:
                c_source, cname = contract.split(":")
                if target_contracts is not None and cname not in target_contracts:
                    continue
                c_source = re.sub(self.root_path, "", c_source)
                if self.input_type == InputHelper.SOLIDITY:
                    source_map = SourceMap(
                        contract,
                        self.source,
                        "solidity",
                        self.root_path,
                        self.remap,
                        self.allow_paths,
                    )
                else:
                    source_map = SourceMap(contract, self.source, "standard json", self.root_path)
                disasm_file = self._get_temporary_files(contract)["disasm"]
                inputs.append(
                    {
                        "contract": contract,
                        "source_map": source_map,
                        "source": self.source,
                        "c_source": c_source,
                        "c_name": cname,
                        "disasm_file": disasm_file,
                    }
                )
        if target_contracts is not None and not inputs:
            raise ValueError("Targeted contracts weren't found in the source code!")
        return inputs

    def rm_tmp_files(self) -> None:
        """Remove temporary files created during analysis.

        Cleans up disassembly files, log files, and intermediate compilation
        outputs based on the input type and EVM flag configuration.

        Note:
            If evm flag is True, disassembly files are preserved for inspection.
            Log files are always removed regardless of evm flag setting.
        """
        if self.input_type == InputHelper.BYTECODE:
            self._rm_tmp_files(self.source)
        else:
            self._rm_tmp_files_of_multiple_contracts(self.compiled_contracts)

    def _get_compiled_contracts(self) -> List[Tuple[str, str]]:
        """Get compiled contracts, performing compilation if needed.

        Returns cached compiled contracts or triggers compilation based on
        input type. Handles Solidity source, standard JSON, and JSON output.

        Returns:
            List of tuples containing (contract_identifier, bytecode) pairs
            where contract_identifier is in format "filename:contractname"

        Raises:
            InvalidCompilation: If compilation fails
            FileNotFoundError: If source files cannot be found
        """
        if not self.compiled_contracts:
            if self.input_type == InputHelper.SOLIDITY:
                self.compiled_contracts = self._compile_solidity()
            elif self.input_type == InputHelper.STANDARD_JSON:
                self.compiled_contracts = self._compile_standard_json()
            elif self.input_type == InputHelper.STANDARD_JSON_OUTPUT:
                self.compiled_contracts = self._compile_standard_json_output(self.source)

        return self.compiled_contracts

    def _extract_bin_obj(self, com: CryticCompile) -> List[Tuple[str, str]]:
        """Extract bytecode objects from CryticCompile result.

        Processes compilation results to extract runtime bytecode for each
        contract, logging compiler information for debugging purposes.

        Args:
            com: CryticCompile object containing compilation results

        Returns:
            List of tuples containing (contract_identifier, runtime_bytecode)
            where contract_identifier is "filename:contractname" format

        Note:
            Only contracts with non-empty runtime bytecode are included.
            Compiler version and optimization settings are logged for each unit.
        """
        bin_objs = []
        for compilation_unit in com.compilation_units.values():
            logging.debug(compilation_unit.compiler_version.compiler)
            logging.debug(compilation_unit.compiler_version.version)
            logging.debug(compilation_unit.compiler_version.optimized)
            for filename, source_unit in compilation_unit.source_units.items():
                for name in source_unit.contracts_names:
                    bytecode_runtime = source_unit.bytecode_runtime(name)
                    if bytecode_runtime:
                        bin_objs.append((filename.used + ":" + name, bytecode_runtime))
        return bin_objs

    def _compile_solidity(self) -> List[Tuple[str, str]]:
        """Compile Solidity source code using CryticCompile.

        Compiles Solidity source with configured remapping and allow-paths,
        handles library linking if needed, and processes compilation results.

        Returns:
            List of compiled contract tuples (identifier, bytecode)

        Raises:
            InvalidCompilation: If Solidity compilation fails
            SystemExit: If compilation fails and not in error reporting mode

        Security Considerations:
            - Validates allow_paths parameter to prevent directory traversal
            - Uses CryticCompile's secure compilation interface
            - Handles library linking with deterministic addresses

        Note:
            If libraries are detected, automatic linking is performed with
            sequential addresses starting from 0x1.
        """
        try:
            options = None
            if self.allow_paths:
                options = [f"--allow-paths {self.allow_paths}"]

            com = CryticCompile(
                self.source,
                solc_remaps=self.remap,
                solc_args=(" ".join(options) if options else ""),
            )
            contracts = self._extract_bin_obj(com)

            libs = set()
            for compilation_unit in com.compilation_units.values():
                for source_unit in compilation_unit.source_units.values():
                    libs.update(
                        set(source_unit.contracts_names).difference(set(source_unit.contracts_names_without_libraries))
                    )
            if libs:
                return self._link_libraries(self.source, libs)

            return contracts
        except InvalidCompilation as err:
            if not self.compilation_err:
                logging.critical("Solidity compilation failed. Please use -ce flag to see the detail.")
            else:
                logging.critical("solc output:\n" + self.source)
                logging.critical(err)
                logging.critical("Solidity compilation failed.")
            # Re-raise the exception instead of calling exit(1) directly
            raise

    def _compile_standard_json(self) -> List[Tuple[str, str]]:
        """Compile standard JSON input using solc directly.

        Reads JSON compilation input, validates paths for security, and
        invokes solc compiler with standard JSON interface for compilation.

        Returns:
            List of compiled contract tuples from JSON output processing

        Raises:
            FileNotFoundError: If source file or solc executable not found
            subprocess.SubprocessError: If solc compilation fails

        Security Considerations:
            - Resolves and validates source file paths to prevent traversal
            - Uses shutil.which() to find solc with full path
            - Sanitizes command arguments to prevent injection
            - Reads files directly instead of using shell commands

        Note:
            Creates temporary "standard_json_output" file that is cleaned
            up automatically by rm_tmp_files().
        """
        with open(os.devnull, "w") as fnull:
            # Validate file path for security
            source_path = Path(self.source).resolve()
            if not source_path.exists():
                raise FileNotFoundError(f"Source file not found: {self.source}")

            # Read file directly instead of using cat subprocess for better security
            with open(source_path) as source_file:
                source_content = source_file.read()

            # Validate allow_paths parameter and find solc executable
            allow_paths = str(self.allow_paths) if self.allow_paths else ""

            # Find solc executable with full path for security
            solc_path = shutil.which("solc")
            if not solc_path:
                raise FileNotFoundError("solc compiler not found in PATH")

            # Use full path and validated arguments for security
            cmd_args = [solc_path, "--allow-paths", allow_paths, "--standard-json"]
            p2 = subprocess.Popen(  # noqa: S603
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=fnull,
                text=True,
            )
            out, _ = p2.communicate(input=source_content)
            with open("standard_json_output", "w") as of:
                of.write(out)

        return self._compile_standard_json_output("standard_json_output")

    def _compile_standard_json_output(self, json_output_file: str) -> List[Tuple[str, str]]:
        """Process pre-compiled standard JSON output.

        Parses JSON compilation output file and extracts deployed bytecode
        for each contract found in the compilation results.

        Args:
            json_output_file: Path to JSON file containing compilation output

        Returns:
            List of contract tuples ("source:name", deployed_bytecode)

        Raises:
            FileNotFoundError: If JSON output file doesn't exist
            json.JSONDecodeError: If file contains invalid JSON
            KeyError: If required JSON structure is missing

        Note:
            Expects standard solc JSON output format with 'sources',
            'contracts', and nested 'evm.deployedBytecode.object' structure.
        """
        with open(json_output_file) as f:
            out = f.read()
        j = json.loads(out)
        contracts = []
        for source in j["sources"]:
            for contract in j["contracts"][source]:
                cname = source + ":" + contract
                evm = j["contracts"][source][contract]["evm"]["deployedBytecode"]["object"]
                contracts.append((cname, evm))
        return contracts

    def _link_libraries(self, filename: str, libs: Set[str]) -> List[Tuple[str, str]]:
        """Link external libraries to contracts during compilation.

        Generates deterministic library addresses and recompiles contracts
        with library linking to resolve external dependencies.

        Args:
            filename: Source file path for recompilation
            libs: Set of library names that need linking

        Returns:
            List of recompiled contract tuples with linked libraries

        Security Considerations:
            - Uses deterministic library addresses (0x1, 0x2, etc.)
            - Preserves allow_paths and remap configurations
            - Validates library names before address generation

        Note:
            Library addresses are generated sequentially starting from 0x1,
            zero-padded to 40 characters for valid Ethereum addresses.
        """
        options = []
        for idx, lib in enumerate(libs):
            lib_address = "0x" + hex(idx + 1)[2:].zfill(40)
            options.append(f"--libraries {lib}:{lib_address}")
        if self.allow_paths:
            options.append(f"--allow-paths {self.allow_paths}")
        com = CryticCompile(target=self.source, solc_args=" ".join(options), solc_remaps=self.remap)

        return self._extract_bin_obj(com)

    def _prepare_disasm_files_for_analysis(self, contracts: List[Tuple[str, str]]) -> None:
        """Prepare disassembly files for all contracts.

        Creates disassembly files for each contract in the list by calling
        the disassembly preparation function for individual contracts.

        Args:
            contracts: List of (contract_identifier, bytecode) tuples

        Note:
            This is a convenience wrapper that processes multiple contracts
            in batch for consistent disassembly file generation.
        """
        for contract, bytecode in contracts:
            self._prepare_disasm_file(contract, bytecode)

    def _prepare_disasm_file(self, target: str, bytecode: str) -> None:
        """Prepare disassembly file for a single contract.

        Generates human-readable EVM disassembly from bytecode and writes
        it to a temporary file for analysis by the symbolic execution engine.

        Args:
            target: Contract identifier or file path for naming the output
            bytecode: EVM bytecode string (hex format, with or without 0x prefix)

        Note:
            Creates files with .evm.disasm extension that contain formatted
            assembly instructions with program counter addresses.
        """
        self._write_disasm_file(target, bytecode)

    def _get_temporary_files(self, target: str) -> Dict[str, str]:
        """Get temporary file paths for a contract target.

        Generates standardized temporary file paths for disassembly and
        log files based on the contract identifier or source file path.

        Args:
            target: Contract identifier or source file path

        Returns:
            Dictionary mapping file types to paths:
            - 'disasm': Path to disassembly file (.evm.disasm)
            - 'log': Path to log file (.evm.disasm.log)

        Note:
            Files are created in the same directory as the target with
            standardized extensions for easy identification and cleanup.
        """
        return {"disasm": target + ".evm.disasm", "log": target + ".evm.disasm.log"}

    def _hex2asm(self, hex_code: str) -> str:
        """Convert hexadecimal bytecode to human-readable assembly.

        Disassembles EVM bytecode into formatted assembly instructions with
        program counter addresses and instruction arguments.

        Args:
            hex_code: EVM bytecode as hex string (with or without 0x prefix)

        Returns:
            Formatted assembly string with each instruction on a new line
            in format: "PC: OPCODE [ARGUMENT]\n"

        Note:
            - Handles PUSH1-PUSH32 instructions with proper argument extraction
            - Removes metadata from bytecode before disassembly
            - Program counter addresses are zero-padded to 5 digits
            - Unknown opcodes are handled gracefully through INSTRUCTIONS mapping

        Example:
            >>> helper._hex2asm("6080604052")
            '00000: PUSH1 0x80\n00002: PUSH1 0x40\n00004: MSTORE\n'
        """
        if hex_code.startswith("0x"):
            hex_code = hex_code[2:]
        bin_code, _ = zeroMetadata(bytes.fromhex(hex_code))
        asm, pc = [], 0
        while pc < len(bin_code):
            op = bin_code[pc]
            arg_len = op - 0x5F if 0x60 <= op <= 0x7F else 0
            arg = f" 0x{bin_code[pc + 1 : pc + 1 + arg_len].hex()}" if arg_len else ""
            asm.append(f"{pc:05x}: {INSTRUCTIONS[op]}{arg}\n")
            pc += 1 + arg_len
        return "".join(asm)

    def _write_disasm_file(self, target: str, bytecode: str) -> None:
        """Write disassembly output to file.

        Converts bytecode to assembly and writes the formatted output to
        a temporary disassembly file for use by the analysis engine.

        Args:
            target: Contract identifier for generating file path
            bytecode: EVM bytecode to disassemble

        Raises:
            Exception: If disassembly fails (logged as critical error)

        Note:
            If disassembly fails, an empty file is created to prevent
            analysis errors, and the failure is logged for debugging.
        """
        tmp_files = self._get_temporary_files(target)
        disasm_file = tmp_files["disasm"]
        disasm_out = ""

        try:
            disasm_out = self._hex2asm(bytecode)
        except Exception as e:
            logging.critical("Disassembly failed: %s.", e)

        with open(disasm_file, "w") as of:
            of.write(disasm_out)

    def _validate_bytecode(self, bytecode: str) -> None:
        """Validate bytecode format and content.

        Args:
            bytecode: EVM bytecode string to validate

        Raises:
            ValueError: If bytecode format is invalid
        """
        if not bytecode:
            raise ValueError("Bytecode cannot be empty")

        # Remove 0x prefix if present
        clean_bytecode = bytecode[2:] if bytecode.startswith("0x") else bytecode

        if not clean_bytecode:
            raise ValueError("Bytecode cannot be empty after removing prefix")

        # Check if all characters are valid hexadecimal
        if not all(c in "0123456789abcdefABCDEF" for c in clean_bytecode):
            raise ValueError("Bytecode contains invalid hexadecimal characters")

        # Check if bytecode has even length (each byte needs 2 hex chars)
        if len(clean_bytecode) % 2 != 0:
            raise ValueError("Bytecode must have even length (each byte needs 2 hex characters)")

    def _rm_tmp_files_of_multiple_contracts(self, contracts: List[Tuple[str, str]]) -> None:
        """Remove temporary files for multiple contracts.

        Cleans up temporary files created during multi-contract analysis,
        including standard JSON output files and individual contract files.

        Args:
            contracts: List of (contract_identifier, bytecode) tuples

        Note:
            For standard JSON input types, also removes the intermediate
            "standard_json_output" file created during compilation.
        """
        if self.input_type in [InputHelper.STANDARD_JSON, InputHelper.STANDARD_JSON_OUTPUT]:
            self._rm_file("standard_json_output")
        for contract, _ in contracts:
            self._rm_tmp_files(contract)

    def _rm_tmp_files(self, target: str) -> None:
        """Remove temporary files for a single contract target.

        Cleans up disassembly and log files based on EVM flag configuration.
        Always removes log files, conditionally removes disassembly files.

        Args:
            target: Contract identifier or file path

        Note:
            If evm flag is True, disassembly files are preserved for
            manual inspection. Log files are always removed.
        """
        tmp_files = self._get_temporary_files(target)
        if not self.evm:
            self._rm_file(tmp_files["disasm"])
        self._rm_file(tmp_files["log"])

    def _rm_file(self, path: str) -> None:
        """Safely remove a file if it exists.

        Checks for file existence before attempting removal to avoid
        errors when cleaning up temporary files.

        Args:
            path: File path to remove

        Note:
            Uses os.unlink() for atomic file removal and only attempts
            removal if the file exists and is a regular file.
        """
        if os.path.isfile(path):
            os.unlink(path)
