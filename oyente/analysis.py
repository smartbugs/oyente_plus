"""Smart contract analysis module.

This module provides the core analysis functionality for Oyente+, including
symbolic execution state management, gas calculation, vulnerability detection,
and feasibility checking for execution paths.

Key Components:
    - Analysis state initialization and management
    - Gas cost calculation for EVM opcodes
    - Reentrancy vulnerability detection
    - Path feasibility analysis for concurrency bug detection

Security Considerations:
    - Uses Z3 constraint solving for symbolic execution
    - Implements timeout handling to prevent infinite loops
    - Validates execution paths for security vulnerabilities

Example:
    >>> analysis = init_analysis()
    >>> gas_cost, mem_cost = calculate_gas('SSTORE', stack, mem, state, analysis, solver)
    >>> is_vulnerable = check_reentrancy_bug(path_conditions, stack, state)
"""

import logging
import math
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import global_params
from opcodes import GCOST
from opcodes import get_ins_cost
from utils import *  # noqa: F403
from vargenerator import *  # noqa: F403
from z3 import And
from z3 import BitVec
from z3 import Not
from z3 import Or
from z3 import Solver
from z3 import is_expr
from z3 import sat
from z3 import simplify
from z3 import unsat


log = logging.getLogger(__name__)

# Global variable to track current file being analyzed
cur_file: Optional[str] = None


def set_cur_file(c_file: str) -> None:
    """Set the current file being analyzed.

    Args:
        c_file: Path to the contract file being analyzed
    """
    global cur_file
    cur_file = c_file


def init_analysis() -> Dict[str, Any]:
    """Initialize analysis data structure.

    Creates a new analysis state dictionary to track various metrics
    and vulnerabilities during symbolic execution.

    Returns:
        Dictionary containing initial analysis state:
        - gas: Total gas consumed during execution
        - gas_mem: Memory gas cost
        - money_flow: List of value transfer operations
        - reentrancy_bug: List of detected reentrancy vulnerabilities
        - money_concurrency_bug: List of potential concurrency issues
        - time_dependency_bug: Dictionary of timestamp dependency issues
    """
    analysis: Dict[str, Any] = {
        "gas": 0,
        "gas_mem": 0,
        "money_flow": [("Is", "Ia", "Iv")],  # (source, destination, amount)
        "reentrancy_bug": [],
        "money_concurrency_bug": [],
        "time_dependency_bug": {},
    }
    return analysis


def display_analysis(analysis: Dict[str, Any]) -> None:
    """Display analysis results for debugging.

    Args:
        analysis: Analysis state dictionary containing money flow data
    """
    logging.debug("Money flow: " + str(analysis["money_flow"]))


def check_reentrancy_bug(
    path_conditions_and_vars: Dict[str, Any], stack: List[Any], global_state: Dict[str, Any]
) -> bool:
    """Check if a CALL instruction has reentrancy vulnerability.

    **Attack Vector**: External calls that allow re-entering the contract
    before state changes are finalized, enabling attackers to drain funds.

    **Detection Logic**: Identifies patterns where:
    1. External calls are made with sufficient gas (> 2300)
    2. Transfer amount exceeds initial value deposit
    3. Storage variables are accessible after the call

    Args:
        path_conditions_and_vars: Dictionary containing path conditions and variables
        stack: EVM stack state with call parameters [gas, recipient, value, ...]
        global_state: Global contract state including storage

    Returns:
        True if reentrancy vulnerability detected, False otherwise

    Note:
        Uses Z3 constraint solving to determine if vulnerable execution paths exist.
        Timeout is configured via global_params.TIMEOUT.
    """
    path_condition = path_conditions_and_vars["path_condition"]
    new_path_condition = []
    for expr in path_condition:
        if not is_expr(expr):
            continue
        list_vars = get_vars(expr)
        for var in list_vars:
            # check if a var is global
            if is_storage_var(var):
                pos = get_storage_position(var)
                if pos in global_state["Ia"]:
                    new_path_condition.append(var == global_state["Ia"][pos])
    transfer_amount = stack[2]
    if isSymbolic(transfer_amount) and is_storage_var(transfer_amount):
        pos = get_storage_position(transfer_amount)
        if pos in global_state["Ia"]:
            new_path_condition.append(global_state["Ia"][pos] != 0)
    if global_params.DEBUG_MODE:
        log.info("=>>>>>> New PC: " + str(new_path_condition))

    solver = Solver()
    solver.set("timeout", global_params.TIMEOUT)
    solver.add(path_condition)
    solver.add(new_path_condition)
    # 2300 is the outgas used by transfer and send.
    # If outgas > 2300 when using call.gas.value then the contract will be considered to contain reentrancy bug
    solver.add(stack[0] > 2300)
    # transfer_amount > deposit_amount => reentrancy
    solver.add(stack[2] > BitVec("Iv", 256))
    # if it is not feasible to re-execute the call, its not a bug
    ret_val: bool = solver.check() != unsat
    if global_params.DEBUG_MODE:
        log.info("Reentrancy_bug? " + str(ret_val))
    return ret_val


def calculate_gas(
    opcode: str,
    stack: List[Any],
    mem: Dict[Any, Any],
    global_state: Dict[str, Any],
    analysis: Dict[str, Any],
    solver: Any,
) -> Tuple[int, int]:
    """Calculate gas cost for EVM opcode execution.

    Computes both the instruction gas cost and memory expansion cost
    for a given opcode execution. Handles both concrete and symbolic values.

    Args:
        opcode: EVM opcode name (e.g., 'SSTORE', 'CALL', 'SHA3')
        stack: Current EVM stack state
        mem: Memory state dictionary
        global_state: Global contract state including storage
        analysis: Current analysis state
        solver: Z3 solver instance for constraint checking

    Returns:
        Tuple of (gas_increment, new_gas_memory):
        - gas_increment: Additional gas cost for this operation
        - new_gas_memory: Updated memory gas cost

    Note:
        For symbolic values, only base costs are added for simplicity.
        Complex opcodes like SSTORE have state-dependent costs.
    """
    gas_increment = get_ins_cost(opcode)  # base cost
    gas_memory = analysis["gas_mem"]
    # In some opcodes, gas cost is not only depend on opcode itself but also current state of evm
    # For symbolic variables, we only add base cost part for simplicity
    if opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4") and len(stack) > 1:
        if isReal(stack[1]):
            gas_increment += GCOST["Glogdata"] * stack[1]
    elif opcode == "EXP" and len(stack) > 1:
        if isReal(stack[1]) and stack[1] > 0:
            gas_increment += GCOST["Gexpbyte"] * (1 + math.floor(math.log(stack[1], 256)))
    elif opcode == "EXTCODECOPY" and len(stack) > 2:
        if isReal(stack[2]):
            gas_increment += GCOST["Gcopy"] * math.ceil(stack[2] / 32)
    elif opcode in ("CALLDATACOPY", "CODECOPY") and len(stack) > 3:
        if isReal(stack[3]):
            gas_increment += GCOST["Gcopy"] * math.ceil(stack[3] / 32)
    elif opcode == "SSTORE" and len(stack) > 1:
        if isReal(stack[1]):
            try:
                try:
                    storage_value = global_state["Ia"][int(stack[0])]
                except (KeyError, TypeError):
                    storage_value = global_state["Ia"][str(stack[0])]
                # when we change storage value from zero to non-zero
                if storage_value == 0 and stack[1] != 0:
                    gas_increment += GCOST["Gsset"]
                else:
                    gas_increment += GCOST["Gsreset"]
            except (KeyError, TypeError):  # when storage address at considered key is empty
                if stack[1] != 0:
                    gas_increment += GCOST["Gsset"]
                elif stack[1] == 0:
                    gas_increment += GCOST["Gsreset"]
        else:
            try:
                try:
                    storage_value = global_state["Ia"][int(stack[0])]
                except (KeyError, TypeError):
                    storage_value = global_state["Ia"][str(stack[0])]
                solver.push()
                solver.add(Not(And(storage_value == 0, stack[1] != 0)))
                if solver.check() == unsat:
                    gas_increment += GCOST["Gsset"]
                else:
                    gas_increment += GCOST["Gsreset"]
                solver.pop()
            except Exception as e:
                if str(e) == "canceled":
                    solver.pop()
                solver.push()
                solver.add(Not(stack[1] != 0))
                if solver.check() == unsat:
                    gas_increment += GCOST["Gsset"]
                else:
                    gas_increment += GCOST["Gsreset"]
                solver.pop()
    elif opcode == "SUICIDE" and len(stack) > 1:
        if isReal(stack[1]):
            address = stack[1] % 2**160
            if address not in global_state:
                gas_increment += GCOST["Gnewaccount"]
        else:
            address = str(stack[1])
            if address not in global_state:
                gas_increment += GCOST["Gnewaccount"]
    elif opcode in ("CALL", "CALLCODE", "DELEGATECALL") and len(stack) > 2:
        # Not fully correct yet
        gas_increment += GCOST["Gcall"]
        if isReal(stack[2]):
            if stack[2] != 0:
                gas_increment += GCOST["Gcallvalue"]
        else:
            solver.push()
            solver.add(Not(stack[2] != 0))
            if check_sat(solver) == unsat:
                gas_increment += GCOST["Gcallvalue"]
            solver.pop()
    # see https://github.com/enzymefinance/oyente/commit/5c3aca6477f2e0c9ad94cb68141495b106a89267
    elif opcode == "SHA3" and isReal(stack[1]):
        gas_increment += GCOST["Gsha3word"] * math.ceil(stack[1] / 32)
    elif opcode == "CREATE2" and isReal(stack[2]):
        gas_increment += GCOST["Gsha3word"] * math.ceil(stack[2] / 32)

    # Calculate gas memory, add it to total gas used
    length = len(mem.keys())  # number of memory words
    new_gas_memory = GCOST["Gmemory"] * length + (length**2) // 512
    gas_increment += new_gas_memory - gas_memory

    return (gas_increment, new_gas_memory)


def update_analysis(
    analysis: Dict[str, Any],
    opcode: str,
    stack: List[Any],
    mem: Dict[Any, Any],
    global_state: Dict[str, Any],
    path_conditions_and_vars: Dict[str, Any],
    solver: Any,
) -> None:
    """Update analysis state based on opcode execution.

    Processes EVM opcodes and updates the analysis state with gas costs,
    money flow tracking, and vulnerability detection results.

    Args:
        analysis: Analysis state dictionary to update
        opcode: EVM opcode being executed
        stack: Current EVM stack state
        mem: Memory state dictionary
        global_state: Global contract state
        path_conditions_and_vars: Path conditions and symbolic variables
        solver: Z3 solver instance

    Side Effects:
        - Updates gas costs in analysis
        - Tracks money flow for CALL and SUICIDE opcodes
        - Detects and records reentrancy vulnerabilities
        - Records potential concurrency issues
    """
    gas_increment, gas_memory = calculate_gas(opcode, stack, mem, global_state, analysis, solver)
    analysis["gas"] += gas_increment
    analysis["gas_mem"] = gas_memory

    if opcode == "CALL":
        recipient = stack[1]
        transfer_amount = stack[2]
        if isReal(transfer_amount) and transfer_amount == 0:
            return
        if isSymbolic(recipient):
            recipient = simplify(recipient)

        reentrancy_result = check_reentrancy_bug(path_conditions_and_vars, stack, global_state)
        analysis["reentrancy_bug"].append(reentrancy_result)

        analysis["money_concurrency_bug"].append(global_state["pc"])
        analysis["money_flow"].append(("Ia", str(recipient), str(transfer_amount)))
    elif opcode == "SUICIDE":
        recipient = stack[0]
        if isSymbolic(recipient):
            recipient = simplify(recipient)
        analysis["money_concurrency_bug"].append(global_state["pc"])
        analysis["money_flow"].append(("Ia", str(recipient), "all_remaining"))


def is_feasible(prev_pc: List[Any], gstate: Dict[Any, Any], curr_pc: List[Any]) -> bool:
    """Check if execution path is feasible after a previous path.

    Determines whether it's possible to execute a current path after
    a previous path has been executed, considering storage state changes.

    Args:
        prev_pc: Previous path conditions (constraints)
        gstate: Global storage state after previous path execution
        curr_pc: Current path conditions to check feasibility

    Returns:
        True if current path is feasible after previous path, False otherwise

    Note:
        Uses Z3 constraint solving to check satisfiability of combined conditions.
        Timeout is configured via global_params.TIMEOUT.
    """
    curr_pc = list(curr_pc)
    new_pc = []
    for var in get_all_vars(curr_pc):
        if is_storage_var(var):
            pos = get_storage_position(var)
            if pos in gstate:
                new_pc.append(var == gstate[pos])
    curr_pc += new_pc
    curr_pc += prev_pc
    solver = Solver()
    solver.set("timeout", global_params.TIMEOUT)
    solver.add(curr_pc)
    result: bool = solver.check() != unsat
    return result


def is_false_positive(i: int, j: int, all_gs: List[Dict[Any, Any]], path_conditions: List[List[Any]]) -> bool:
    """Detect if two execution paths don't have a real race condition.

    Analyzes whether executing path j after path i is actually possible,
    helping to reduce false positives in concurrency bug detection.

    **Detection Strategy**:
    1. Check if path i modifies storage variables that make path j infeasible
    2. Verify if paths have mutually exclusive conditions (e.g., if/else branches)
    3. Additional semantic checks for path compatibility

    Args:
        i: Index of the first execution path
        j: Index of the second execution path
        all_gs: List of global states for all paths
        path_conditions: List of path conditions for all execution paths

    Returns:
        True if the race condition is a false positive, False if it's real

    Note:
        Uses variable renaming and constraint solving to check path feasibility.
    """
    pathi = path_conditions[i]
    pathj = path_conditions[j]
    statei = all_gs[i]

    # rename global variables in path i
    set_of_pcs, statei = rename_vars(pathi, statei)
    log.debug("Set of PCs after renaming global vars" + str(set_of_pcs))
    log.debug("Global state values in path " + str(i) + " after renaming: " + str(statei))
    return not is_feasible(set_of_pcs, statei, pathj)


def is_diff(flow1: List[Tuple[Any, Any, Any]], flow2: List[Tuple[Any, Any, Any]]) -> int:
    """Check if two money flows are different.

    Compares two sequences of money transfer operations to determine
    if they represent different execution outcomes.

    Args:
        flow1: First money flow sequence [(source, dest, amount), ...]
        flow2: Second money flow sequence [(source, dest, amount), ...]

    Returns:
        1 if flows are different, 0 if they are equivalent

    Note:
        Uses Z3 constraint solving to handle symbolic values in flow comparisons.
        Returns 1 (different) if any constraint solving fails.
    """
    if len(flow1) != len(flow2):
        return 1
    n = len(flow1)
    for i in range(n):
        if flow1[i] == flow2[i]:
            continue
        try:
            tx_cd = Or(
                Not(flow1[i][0] == flow2[i][0]), Not(flow1[i][1] == flow2[i][1]), Not(flow1[i][2] == flow2[i][2])
            )
            solver = Solver()
            solver.set("timeout", global_params.TIMEOUT)
            solver.add(tx_cd)

            if solver.check() == sat:
                return 1
        except Exception:
            return 1
    return 0
