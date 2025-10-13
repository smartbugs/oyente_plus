"""Global configuration parameters for Oyente symbolic execution engine.

This module contains all global configuration parameters that control
the behavior of the Oyente smart contract analyzer. These parameters
can be modified at runtime based on command-line arguments.
"""

from typing import Optional


# enable reporting of the result
REPORT_MODE: int = 0
"""Enable generation of detailed analysis reports (0=disabled, 1=enabled)."""

# print everything in the console
PRINT_MODE: int = 0
"""Enable verbose console output (0=disabled, 1=enabled)."""

# enable log file to print all exception
DEBUG_MODE: int = 0
"""Enable debug logging with exception details (0=disabled, 1=enabled)."""

# check false positive in concurrency
CHECK_CONCURRENCY_FP: int = 0
"""Enable false positive checking for concurrency bugs (0=disabled, 1=enabled)."""

# Timeout for z3 in ms
TIMEOUT: int = 100
"""Timeout for Z3 solver operations in milliseconds."""


# timeout to run symbolic execution (in secs)
GLOBAL_TIMEOUT: int = 50
"""Global timeout for symbolic execution in seconds."""


# print path conditions
PRINT_PATHS: int = 0
"""Enable printing of path conditions (0=disabled, 1=enabled)."""

# Redirect results to a json file.
STORE_RESULT: int = 0
"""Store analysis results in JSON file (0=disabled, 1=enabled)."""

# depth limit for DFS
DEPTH_LIMIT: int = 50
"""Maximum depth for depth-first search in symbolic execution."""

GAS_LIMIT: int = 4000000
"""Maximum gas limit for contract execution."""

LOOP_LIMIT: int = 10
"""Maximum number of iterations for loop execution."""

# Use a public blockchain to speed up the symbolic execution
USE_GLOBAL_BLOCKCHAIN: int = 0
"""Use blockchain state for concrete values (0=disabled, 1=enabled)."""

USE_GLOBAL_STORAGE: int = 0
"""Use global storage state (0=disabled, 1=enabled)."""

# Take state data from state.json to speed up the symbolic execution
INPUT_STATE: int = 0
"""Load initial state from state.json file (0=disabled, 1=enabled)."""

# Check assertions
CHECK_ASSERTIONS: int = 0
"""Check for assertion failures (0=disabled, 1=enabled)."""

GENERATE_TEST_CASES: int = 0
"""Generate test cases for each execution path (0=disabled, 1=enabled)."""

# Run Oyente in parallel
PARALLEL: int = 0
"""Enable parallel symbolic execution (0=disabled, 1=enabled)."""

# Iterable of targeted smart contract names
TARGET_CONTRACTS: Optional[list[str]] = None
"""List of specific contract names to analyze (None=analyze all)."""
