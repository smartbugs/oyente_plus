#!/usr/bin/env python
"""Oyente - Smart contract vulnerability analyzer.

This is the main entry point for the Oyente smart contract analyzer.
It provides a command-line interface for analyzing Ethereum smart contracts
for security vulnerabilities using symbolic execution.
"""

import argparse
import logging
import re
import shutil
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

import global_params
import requests
import symExec
from crytic_compile import InvalidCompilation  # type: ignore[attr-defined]
from input_helper import InputHelper


def cmd_exists(cmd: str) -> bool:
    """Check if a command exists in the system PATH.

    Args:
        cmd: The command name to check

    Returns:
        True if the command exists, False otherwise
    """
    # Use shutil.which() for better security and portability
    return shutil.which(cmd) is not None


def compare_versions(version1: str, version2: str) -> int:
    """Compare two version strings.

    Args:
        version1: First version string (e.g., "1.2.3")
        version2: Second version string (e.g., "1.2.4")

    Returns:
        -1 if version1 < version2
         0 if version1 == version2
         1 if version1 > version2
    """

    def normalize(v: str) -> List[int]:
        return [int(x) for x in re.sub(r"(\.0+)*$", "", v).split(".")]

    v1_normalized = normalize(version1)
    v2_normalized = normalize(version2)
    # Python 3 compatible comparison (cmp was removed in Python 3)
    return int((v1_normalized > v2_normalized) - (v1_normalized < v2_normalized))


def has_dependencies_installed() -> bool:
    """Check if all required dependencies are installed.

    Verifies that Z3 solver and Solidity compiler are available
    and checks their versions for compatibility.

    Returns:
        True if all dependencies are satisfied, False otherwise
    """
    try:
        import z3
        import z3.z3util

        z3_version = z3.get_version_string()
        tested_z3_version = "4.14.1.0"
        if compare_versions(z3_version, tested_z3_version) > 0:
            logging.warning(
                f"You are using an untested version of z3. {tested_z3_version} is the officially tested version"
            )
    except Exception as e:
        logging.critical(e)
        logging.critical("Z3 is not available. Please install z3 from https://github.com/Z3Prover/z3.")
        return False

    if not cmd_exists("solc"):
        logging.critical("solc is missing. Please install the solidity compiler and make sure solc is in the path.")
        return False

    return True


def analyze_bytecode(args: argparse.Namespace) -> int:
    """Analyze EVM bytecode for vulnerabilities.

    Args:
        args: Command-line arguments from argparse

    Returns:
        Exit code (0 for success, 1 for errors found)
    """

    helper = InputHelper(InputHelper.BYTECODE, source=args.source, evm=args.evm)
    try:
        inp = helper.get_inputs()[0]
        result = symExec.run(disasm_file=inp["disasm_file"])
        helper.rm_tmp_files()

        # Return 1 if vulnerabilities found, 0 otherwise
        exit_code = 1 if result.get("vulnerability_count", 0) > 0 else 0
        return exit_code
    except OSError as e:
        # File not found or can't be read
        logging.critical(f"Error reading bytecode file '{args.source}': {e}")
        helper.rm_tmp_files()
        return 1
    except ValueError as e:
        # Invalid bytecode format
        logging.critical(f"Invalid bytecode format in '{args.source}': {e}")
        helper.rm_tmp_files()
        return 1


def run_solidity_analysis(inputs: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], int]:
    """Run analysis on multiple Solidity contracts.

    Args:
        inputs: List of contract information dictionaries

    Returns:
        Tuple of (results dictionary, exit code)
    """
    results: Dict[str, Any] = {}
    exit_code = 0

    for inp in inputs:
        logging.info("contract %s:", inp["contract"])
        result = symExec.run(
            disasm_file=inp["disasm_file"],
            source_map=inp["source_map"],
            source_file=inp["source"],
        )

        c_source = inp.get("c_source", "unknown")
        c_name = inp.get("c_name", "unknown")
        if c_source not in results:
            results[c_source] = {}
        results[c_source][c_name] = result

        # Set exit code to 1 if vulnerabilities found in this contract
        if result.get("vulnerability_count", 0) > 0:
            exit_code = 1
    return results, exit_code


def analyze_solidity(args: argparse.Namespace, input_type: str = "solidity") -> int:
    """Analyze Solidity source code for vulnerabilities.

    Args:
        args: Command-line arguments from argparse
        input_type: Type of input ('solidity', 'standard_json', 'standard_json_output')

    Returns:
        Exit code (0 for success, 1 for errors found)
    """

    if input_type == "solidity":
        helper = InputHelper(
            InputHelper.SOLIDITY,
            source=args.source,
            evm=args.evm,
            compilation_err=args.compilation_error,
            root_path=args.root_path,
            remap=args.remap,
            allow_paths=args.allow_paths,
        )
    elif input_type == "standard_json":
        helper = InputHelper(
            InputHelper.STANDARD_JSON,
            source=args.source,
            evm=args.evm,
            allow_paths=args.allow_paths,
        )
    elif input_type == "standard_json_output":
        helper = InputHelper(
            InputHelper.STANDARD_JSON_OUTPUT,
            source=args.source,
            evm=args.evm,
        )
    try:
        inputs = helper.get_inputs(global_params.TARGET_CONTRACTS)
        _results, exit_code = run_solidity_analysis(inputs)
        helper.rm_tmp_files()

        return int(exit_code)
    except InvalidCompilation:
        # Compilation failed (including file not found)
        helper.rm_tmp_files()
        return 1


def main() -> int:
    """Main entry point for Oyente analyzer.

    Parses command-line arguments and runs the appropriate analysis
    based on the input type (bytecode or Solidity source).
    """
    # TODO: Implement -o switch.

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-s",
        "--source",
        type=str,
        help="local source file name. Solidity by default. Use -b to process evm instead. Use stdin to read from stdin.",
    )
    group.add_argument(
        "-ru",
        "--remoteURL",
        type=str,
        help="Get contract from remote URL. Solidity by default. Use -b to process evm instead.",
        dest="remote_URL",
    )
    parser.add_argument(
        "-cnames",
        "--target-contracts",
        type=str,
        nargs="+",
        help="The name of targeted contracts. If specified, only the specified contracts in the source code will be processed. By default, all contracts in Solidity code are processed.",
    )
    parser.add_argument("--version", action="version", version="oyente version 0.2.7 - Commonwealth")
    parser.add_argument("-rmp", "--remap", help="Remap directory paths", action="store", type=str)
    parser.add_argument("-t", "--timeout", help="Timeout for Z3 in ms.", action="store", type=int)
    parser.add_argument(
        "-gl",
        "--gaslimit",
        help="Limit Gas",
        action="store",
        dest="gas_limit",
        type=int,
    )
    parser.add_argument(
        "-rp",
        "--root-path",
        help="Root directory path used for the online version",
        action="store",
        dest="root_path",
        type=str,
    )
    parser.add_argument(
        "-ll",
        "--looplimit",
        help="Limit number of loops",
        action="store",
        dest="loop_limit",
        type=int,
    )
    parser.add_argument(
        "-dl",
        "--depthlimit",
        help="Limit DFS depth",
        action="store",
        dest="depth_limit",
        type=int,
    )
    parser.add_argument(
        "-ap",
        "--allow-paths",
        help="Allow a given path for imports",
        action="store",
        dest="allow_paths",
        type=str,
    )
    parser.add_argument(
        "-glt",
        "--global-timeout",
        help="Timeout for symbolic execution",
        action="store",
        dest="global_timeout",
        type=int,
    )

    parser.add_argument("-e", "--evm", help="Do not remove the .evm file.", action="store_true")
    parser.add_argument("-j", "--json", help="Redirect results to a json file.", action="store_true")
    parser.add_argument("-p", "--paths", help="Print path condition information.", action="store_true")
    parser.add_argument("-db", "--debug", help="Display debug information", action="store_true")
    parser.add_argument("-st", "--state", help="Get input state from state.json", action="store_true")
    parser.add_argument("-r", "--report", help="Create .report file.", action="store_true")
    parser.add_argument("-v", "--verbose", help="Verbose output, print everything.", action="store_true")
    parser.add_argument(
        "-pl",
        "--parallel",
        help="Run Oyente in parallel. Note: The performance may depend on the contract",
        action="store_true",
    )
    parser.add_argument(
        "-b",
        "--bytecode",
        help="read bytecode in source instead of solidity file.",
        action="store_true",
    )
    parser.add_argument("-a", "--assertion", help="Check assertion failures.", action="store_true")
    parser.add_argument(
        "-sj",
        "--standard-json",
        help="Support Standard JSON input",
        action="store_true",
    )
    parser.add_argument(
        "-gb",
        "--globalblockchain",
        help="Integrate with the global ethereum blockchain",
        action="store_true",
    )
    parser.add_argument(
        "-ce",
        "--compilation-error",
        help="Display compilation errors",
        action="store_true",
    )
    parser.add_argument(
        "-gtc",
        "--generate-test-cases",
        help="Generate test cases each branch of symbolic execution tree",
        action="store_true",
    )
    parser.add_argument(
        "-sjo",
        "--standard-json-output",
        help="Support Standard JSON output",
        action="store_true",
    )

    args: argparse.Namespace = parser.parse_args()

    if args.root_path:
        if args.root_path[-1] != "/":
            args.root_path += "/"
    else:
        args.root_path = ""

    args.remap = args.remap if args.remap else ""
    args.allow_paths = args.allow_paths if args.allow_paths else ""

    if args.timeout:
        global_params.TIMEOUT = args.timeout

    logging.basicConfig()
    root_logger = logging.getLogger(None)

    if args.verbose:
        root_logger.setLevel(level=logging.DEBUG)
    else:
        root_logger.setLevel(level=logging.INFO)

    global_params.PRINT_PATHS = 1 if args.paths else 0
    global_params.REPORT_MODE = 1 if args.report else 0
    global_params.USE_GLOBAL_BLOCKCHAIN = 1 if args.globalblockchain else 0
    global_params.INPUT_STATE = 1 if args.state else 0
    global_params.STORE_RESULT = 1 if args.json else 0
    global_params.CHECK_ASSERTIONS = 1 if args.assertion else 0
    global_params.DEBUG_MODE = 1 if args.debug else 0
    global_params.GENERATE_TEST_CASES = 1 if args.generate_test_cases else 0
    global_params.PARALLEL = 1 if args.parallel else 0

    if args.target_contracts and args.bytecode:
        parser.error(
            "Targeted contracts cannot be specifed when the bytecode is provided (Instead of Solidity source code)."
        )
    global_params.TARGET_CONTRACTS = args.target_contracts

    if args.depth_limit:
        global_params.DEPTH_LIMIT = args.depth_limit
    if args.gas_limit:
        global_params.GAS_LIMIT = args.gas_limit
    if args.loop_limit:
        global_params.LOOP_LIMIT = args.loop_limit
    if args.global_timeout:
        global_params.GLOBAL_TIMEOUT = args.global_timeout

    if not has_dependencies_installed():
        return 1

    if args.remote_URL:
        r = requests.get(args.remote_URL, timeout=30)  # 30 second timeout
        code = r.text
        filename = "remote_contract.evm" if args.bytecode else "remote_contract.sol"
        args.source = filename
        with open(filename, "w") as f:
            f.write(code)

    exit_code = 0
    if args.bytecode:
        exit_code = analyze_bytecode(args)
    elif args.standard_json:
        exit_code = analyze_solidity(args, input_type="standard_json")
    elif args.standard_json_output:
        exit_code = analyze_solidity(args, input_type="standard_json_output")
    else:
        exit_code = analyze_solidity(args)

    return exit_code


if __name__ == "__main__":
    exit(main())
