# return true if the two paths have different flows of money
# later on we may want to return more meaningful output: e.g. if the concurrency changes
# the amount of money or the recipient.
import csv
import difflib
import json
import mmap
import os
import re
import shlex
import subprocess
from typing import Any
from typing import Union

from z3 import BitVec
from z3 import BitVecVal
from z3 import Z3Exception
from z3 import is_expr
from z3 import substitute
from z3 import unknown
from z3.z3util import get_vars


def ceil32(x: int) -> int:
    return x if x % 32 == 0 else x + 32 - (x % 32)


def isSymbolic(value: Any) -> bool:  # noqa: N802
    return not isinstance(value, int)


def isReal(value: Any) -> bool:  # noqa: N802
    return isinstance(value, int)


def isAllReal(*args: Any) -> bool:  # noqa: N802
    return all(not isSymbolic(element) for element in args)


def to_symbolic(number: Any) -> Any:
    if isReal(number):
        return BitVecVal(number, 256)
    return number


def to_unsigned(number: int) -> int:
    if number < 0:
        return number + 2**256
    return number


def to_signed(number: int) -> int:
    if number > 2 ** (256 - 1):
        return (2 ** (256) - number) * (-1)
    else:
        return number


def check_sat(solver: Any, pop_if_exception: bool = True) -> Any:
    try:
        ret = solver.check()
        if ret == unknown:
            raise Z3Exception(solver.reason_unknown())
    except Exception as e:
        if pop_if_exception:
            solver.pop()
        raise e
    return ret


def custom_deepcopy(input: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in input:
        if isinstance(input[key], list):
            output[key] = list(input[key])
        elif isinstance(input[key], dict):
            output[key] = custom_deepcopy(input[key])
        else:
            output[key] = input[key]
    return output


def is_storage_var(var: Any) -> bool:
    var_name = var.decl().name() if not isinstance(var, str) else var
    return var_name.startswith("Ia_store")


# copy only storage values/ variables from a given global state
# TODO: add balance in the future
def copy_global_values(global_state: dict[str, Any]) -> Any:
    return global_state["Ia"]


# check if a variable is in an expression
def is_in_expr(var: str, expr: Any) -> bool:
    list_vars = get_vars(expr)
    set_vars = {i.decl().name() for i in list_vars}
    return var in set_vars


# check if an expression has any storage variables
def has_storage_vars(expr: Any, storage_vars: list[Any]) -> bool:
    list_vars = get_vars(expr)
    return any(var in storage_vars for var in list_vars)


def get_all_vars(exprs: list[Any]) -> list[Any]:
    ret_vars = []
    for expr in exprs:
        if is_expr(expr):
            ret_vars += get_vars(expr)
    return ret_vars


def get_storage_position(var: Any) -> Union[int, str]:
    var_name = var.decl().name() if not isinstance(var, str) else var
    pos = var_name.split("-")[1]
    try:
        return int(pos)
    except Exception:
        return pos


# Rename variables to distinguish variables in two different paths.
# e.g. Ia_store_0 in path i becomes Ia_store_0_old if Ia_store_0 is modified
# else we must keep Ia_store_0 if its not modified
def rename_vars(pcs: list[Any], global_states: dict[Any, Any]) -> tuple[list[Any], dict[Any, Any]]:
    ret_pcs = []
    vars_mapping: dict[Any, Any] = {}

    for expr in pcs:
        if is_expr(expr):
            list_vars = get_vars(expr)
            for var in list_vars:
                if var in vars_mapping:
                    expr = substitute(expr, (var, vars_mapping[var]))
                    continue
                var_name = var.decl().name()
                # check if a var is global
                if is_storage_var(var):
                    pos = get_storage_position(var)
                    # if it is not modified then keep the previous name
                    if pos not in global_states:
                        continue
                # otherwise, change the name of the variable
                new_var_name = var_name + "_old"
                new_var = BitVec(new_var_name, 256)
                vars_mapping[var] = new_var
                expr = substitute(expr, (var, vars_mapping[var]))
        ret_pcs.append(expr)

    ret_gs = {}
    # replace variable in storage expression
    for storage_addr in global_states:
        expr = global_states[storage_addr]
        # z3 4.1 makes me add this line
        if is_expr(expr):
            list_vars = get_vars(expr)
            for var in list_vars:
                if var in vars_mapping:
                    expr = substitute(expr, (var, vars_mapping[var]))
                    continue
                var_name = var.decl().name()
                # check if a var is global
                if var_name.startswith("Ia_store_"):
                    position = int(var_name.split("_")[len(var_name.split("_")) - 1])
                    # if it is not modified
                    if position not in global_states:
                        continue
                # otherwise, change the name of the variable
                new_var_name = var_name + "_old"
                new_var = BitVec(new_var_name, 256)
                vars_mapping[var] = new_var
                expr = substitute(expr, (var, vars_mapping[var]))
        ret_gs[storage_addr] = expr

    return ret_pcs, ret_gs


# split a file into smaller files
def split_dicts(filename: str, nsub: int = 500) -> None:
    with open(filename) as json_file:
        c = json.load(json_file)
        current_file = {}
        file_index = 1
        for u, v in c.items():
            current_file[u] = v
            if len(current_file) == nsub:
                with open(filename.split(".")[0] + "_" + str(file_index) + ".json", "w") as outfile:
                    json.dump(current_file, outfile)
                    file_index += 1
                    current_file.clear()
        if len(current_file):
            with open(filename.split(".")[0] + "_" + str(file_index) + ".json", "w") as outfile:
                json.dump(current_file, outfile)
                current_file.clear()


def do_split_dicts() -> None:
    for i in range(11):
        split_dicts("contract" + str(i) + ".json")
        os.remove("contract" + str(i) + ".json")


def run_re_file(re_str: str, fn: str) -> list[Any]:
    size = os.stat(fn).st_size
    with open(fn, "rb") as tf:
        data = mmap.mmap(tf.fileno(), size, access=mmap.ACCESS_READ)
        return re.findall(re_str.encode(), data)


def get_contract_info(contract_addr: str) -> tuple[Union[str, list[Any]], Union[str, list[Any]]]:
    print(f"Getting info for contracts... {contract_addr}")
    file_name1 = "tmp/" + contract_addr + "_txs.html"
    file_name2 = "tmp/" + contract_addr + ".html"
    # get number of txs
    txs: Union[str, list[Any]] = "unknown"
    value: Union[str, list[Any]] = "unknown"
    re_txs_value = r"<span>A total of (.+?) transactions found for address</span>"
    re_str_value = r"<td>ETH Balance:\n<\/td>\n<td>\n(.+?)\n<\/td>"
    try:
        txs = run_re_file(re_txs_value, file_name1)
        value = run_re_file(re_str_value, file_name2)
    except Exception:
        try:
            os.system(f"wget -O {file_name1} http://etherscan.io/txs?a={contract_addr}")  # noqa: S605
            re_txs_value = r"<span>A total of (.+?) transactions found for address</span>"
            txs = run_re_file(re_txs_value, file_name1)

            # get balance
            re_str_value = r"<td>ETH Balance:\n<\/td>\n<td>\n(.+?)\n<\/td>"
            os.system(f"wget -O {file_name2} https://etherscan.io/address/{contract_addr}")  # noqa: S605
            value = run_re_file(re_str_value, file_name2)
        except Exception:  # noqa: S110
            # Ignore errors when fetching contract info from external source
            pass
    return txs, value


def get_contract_stats(list_of_contracts: str) -> None:
    with open("concurr.csv", "w") as stats_file:
        fp = csv.writer(stats_file, delimiter=",")
        fp.writerow(["Contract address", "No. of paths", "No. of concurrency pairs", "Balance", "No. of TXs", "Note"])
        with open(list_of_contracts) as f:
            for contract in f.readlines():
                contract_addr = contract.split()[0]
                value, txs = get_contract_info(contract_addr)
                fp.writerow([contract_addr, contract.split()[1], contract.split()[2], value, txs, contract.split()[3:]])


def get_time_dependant_contracts(list_of_contracts: str) -> None:
    with open("time.csv", "w") as stats_file:
        fp = csv.writer(stats_file, delimiter=",")
        fp.writerow(["Contract address", "Balance", "No. of TXs", "Note"])
        with open(list_of_contracts) as f:
            for contract in f.readlines():
                if len(contract.strip()) == 0:
                    continue
                contract_addr = contract.split(".")[0].split("_")[1]
                txs, value = get_contract_info(contract_addr)
                fp.writerow([contract_addr, value, txs])


def get_distinct_contracts(list_of_contracts: str = "concurr.csv") -> None:
    flag = []
    with open(list_of_contracts, "rb") as csvfile:
        contracts = csvfile.readlines()[1:]
        n = len(contracts)
        for i in range(n):
            flag.append(i)  # mark which contract is similar to contract_i
        for i in range(n):
            if flag[i] != i:
                continue
            contract_i = contracts[i].decode().split(",")[0]
            npath_i = int(contracts[i].decode().split(",")[1])
            npair_i = int(contracts[i].decode().split(",")[2])
            file_i = "stats/tmp_" + contract_i + ".evm"
            print(f" reading file {file_i}")
            for j in range(i + 1, n):
                if flag[j] != j:
                    continue
                contract_j = contracts[j].decode().split(",")[0]
                npath_j = int(contracts[j].decode().split(",")[1])
                npair_j = int(contracts[j].decode().split(",")[2])
                if (npath_i == npath_j) and (npair_i == npair_j):
                    file_j = "stats/tmp_" + contract_j + ".evm"

                    with open(file_i) as f1, open(file_j) as f2:
                        code_i = f1.readlines()
                        code_j = f2.readlines()
                        if abs(len(code_i) - len(code_j)) >= 5:
                            continue
                        diff = difflib.ndiff(code_i, code_j)
                        ndiff = 0
                        for line in diff:
                            if line.startswith("+") or line.startswith("-"):
                                ndiff += 1
                        if ndiff < 10:
                            flag[j] = i
    print(flag)


def run_command(cmd: str) -> str:
    with open(os.devnull, "w") as fnull:
        solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=fnull)  # noqa: S603
        result = solc_p.communicate()[0]
        return result.decode("utf-8", "strict")


def run_command_with_err(cmd: str) -> tuple[str, str]:
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603
    out_bytes, err_bytes = solc_p.communicate()
    out = out_bytes.decode("utf-8", "strict")
    err = err_bytes.decode("utf-8", "strict")
    return out, err
