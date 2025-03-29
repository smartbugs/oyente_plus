import logging
import subprocess
import sys

from z3 import *
from global_params import *
from utils import to_unsigned
from test_evm.global_test_params import *


class EvmUnitTest(object):
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def bytecode(self):
        return self.data['exec']['code'][2:]

    def storage(self):
        storage = self.data['post'].values()[0]['storage']
        return storage if storage != None else {"0": "0"}

    def gas_info(self):
        gas_limit = int(self.data['exec']['gas'], 0)
        gas_remaining = int(self.data['gas'], 0)
        return (gas_limit, gas_remaining)

    def run_test(self):
        return self._execute_vm(self.bytecode())

    def compare_with_symExec_result(self, global_state, analysis):
        if UNIT_TEST == 2: return self.compare_real_value(global_state, analysis)
        if UNIT_TEST == 3: return self.compare_symbolic(global_state)

    def compare_real_value(self, global_state, analysis):
        storage_status = self._compare_storage_value(global_state)
        gas_status = self._compare_gas_value(analysis)
        if storage_status != PASS: return storage_status
        if gas_status != PASS: return gas_status
        return PASS

    def compare_symbolic(self, global_state):
        for key, value in self.storage().items():
            key, value = int(key, 0), int(value, 0)
            try:
                symExec_result = global_state['Ia'][str(key)]
            except:
                return EMPTY_RESULT

            s = Solver()
            s.add(symExec_result == BitVecVal(value, 256))
            if s.check() == unsat: # Unsatisfy
                return FAIL
        return PASS

    def is_exception_case(self): # no post, gas field in data
        try:
            post = self.data['post']
            gas = self.data['gas']
            return False
        except:
            return True

    def _execute_vm(self, bytecode):
        self._create_bytecode_file(bytecode)
        try:
            result = subprocess.run(
                [sys.executable, "oyente.py", "-b", "-s", "bytecode"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            print(result.stdout)
            print(result.stderr)
            
            exit_code = result.returncode
            output_str = result.stderr
            
            # Check if the output contains the error message of intended exceptions and set the exit code accordingly
            if  ("Exception: UNKNOWN INSTRUCTION" in output_str):
                exit_code = 3
            elif ("ValueError: STACK underflow" in output_str):
                exit_code = 4

        except Exception as e:
            logging.error("UNKNOWN ERROR: %s", e)
            exit_code = 4

        # Adjust exit_code by + 100 to reach exit codes defined in global_test_params.py
        return exit_code + 100

    def _create_bytecode_file(self, bytecode):
        with open('bytecode', 'w') as code_file:
            code_file.write(bytecode)
            code_file.write('\n')
            code_file.close()

    def _compare_storage_value(self, global_state):
        for key, value in self.storage().items():
            key, value = int(key, 0), int(value, 0)

            try:
                storage = to_unsigned(int(global_state['Ia'][key]))
            except:
                return EMPTY_RESULT

            if storage != value:
                return FAIL
        return PASS

    def _compare_gas_value(self, analysis):
        gas_used = analysis['gas']
        gas_limit, gas_remaining = self.gas_info()
        if gas_used == gas_limit - gas_remaining:
            return PASS
        else:
            return INCORRECT_GAS
