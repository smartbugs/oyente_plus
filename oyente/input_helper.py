import shlex
import subprocess
import os
import re
import logging
import json
import global_params
import six
from source_map import SourceMap
from utils import run_command, run_command_with_err
from crytic_compile import CryticCompile, InvalidCompilation
from evmdasm import EvmBytecode
from pyevmasm import disassemble_hex

class InputHelper:
    BYTECODE = 0
    SOLIDITY = 1
    STANDARD_JSON = 2
    STANDARD_JSON_OUTPUT = 3

    def __init__(self, input_type, **kwargs):
        self.input_type = input_type

        if input_type == InputHelper.BYTECODE:
            attr_defaults = {
                'source': None,
                'evm': False,
                'disassembler': kwargs.get('disasm'),
            }
        elif input_type == InputHelper.SOLIDITY:
            attr_defaults = {
                'source': None,
                'evm': False,
                'root_path': "",
                'compiled_contracts': [],
                'compilation_err': False,
                'remap': "",
                'allow_paths': ""
            }
        elif input_type == InputHelper.STANDARD_JSON:
            attr_defaults = {
                'source': None,
                'evm': False,
                'root_path': "",
                'allow_paths': None,
                'compiled_contracts': []
            }
        elif input_type == InputHelper.STANDARD_JSON_OUTPUT:
            attr_defaults = {
                'source': None,
                'evm': False,
                'root_path': "",
                'compiled_contracts': [],
            }

        for (attr, default) in six.iteritems(attr_defaults):
            val = kwargs.get(attr, default)
            if val == None:
                raise Exception("'%s' attribute can't be None" % attr)
            else:
                setattr(self, attr, val)

    def get_inputs(self, targetContracts=None):
        inputs = []
        if self.input_type == InputHelper.BYTECODE:
            with open(self.source, 'r') as f:
                bytecode = f.read()
            self._prepare_disasm_file(self.source, bytecode)

            disasm_file = self._get_temporary_files(self.source)['disasm']
            inputs.append({'disasm_file': disasm_file})
        else:
            contracts = self._get_compiled_contracts()
            self._prepare_disasm_files_for_analysis(contracts)
            for contract, _ in contracts:
                c_source, cname = contract.split(':')
                if targetContracts is not None and cname not in targetContracts:
                    continue
                c_source = re.sub(self.root_path, "", c_source)
                if self.input_type == InputHelper.SOLIDITY:
                    source_map = SourceMap(contract, self.source, 'solidity', self.root_path, self.remap, self.allow_paths)
                else:
                    source_map = SourceMap(contract, self.source, 'standard json', self.root_path)
                disasm_file = self._get_temporary_files(contract)['disasm']
                inputs.append({
                    'contract': contract,
                    'source_map': source_map,
                    'source': self.source,
                    'c_source': c_source,
                    'c_name': cname,
                    'disasm_file': disasm_file
                })
        if targetContracts is not None and not inputs:
            raise ValueError("Targeted contracts weren't found in the source code!")
        return inputs

    def rm_tmp_files(self):
        if self.input_type == InputHelper.BYTECODE:
            self._rm_tmp_files(self.source)
        else:
            self._rm_tmp_files_of_multiple_contracts(self.compiled_contracts)

    def _get_compiled_contracts(self):
        if not self.compiled_contracts:
            if self.input_type == InputHelper.SOLIDITY:
                self.compiled_contracts = self._compile_solidity()
            elif self.input_type == InputHelper.STANDARD_JSON:
                self.compiled_contracts = self._compile_standard_json()
            elif self.input_type == InputHelper.STANDARD_JSON_OUTPUT:
                self.compiled_contracts = self._compile_standard_json_output(self.source)

        return self.compiled_contracts

    def _extract_bin_obj(self, com: CryticCompile):
        #return [(com.contracts_filenames[name].absolute + ':' + name, com.bytecode_runtime(name)) for name in com.contracts_names if com.bytecode_runtime(name)]
        bin_objs = []
        for compilation_unit in com.compilation_units.values():
            #print(compilation_unit.compiler_version.compiler)
            #print(compilation_unit.compiler_version.version)
            #print(compilation_unit.compiler_version.optimized)
            for filename,source_unit in compilation_unit.source_units.items():
                for name in source_unit.contracts_names:
                    bytecode_runtime = source_unit.bytecode_runtime(name)
                    if bytecode_runtime:
                        bin_objs.append((filename.used+':'+name, bytecode_runtime))
        return bin_objs

    def _compile_solidity(self):
        try:
            options = None
            if self.allow_paths:
                options = [F"--allow-paths {self.allow_paths}"]

            com = CryticCompile(self.source, solc_remaps=self.remap, solc_args=(' '.join(options) if options else None))
            contracts = self._extract_bin_obj(com)

            #libs = com.contracts_names.difference(com.contracts_names_without_libraries)
            libs = set()
            for compilation_unit in com.compilation_units.values():
                for source_unit in compilation_unit.source_units.values():
                    libs.update(source_unit.contracts_names.difference(source_unit.contracts_names_without_libraries))
            if libs:
                return self._link_libraries(self.source, libs)
            
            return contracts
        except InvalidCompilation as err:
            if not self.compilation_err:
                logging.critical("Solidity compilation failed. Please use -ce flag to see the detail.")
                if global_params.WEB:
                    six.print_({"error": "Solidity compilation failed."})
            else:
                logging.critical("solc output:\n" + self.source)
                logging.critical(err)
                logging.critical("Solidity compilation failed.")
                if global_params.WEB:
                    six.print_({"error": err})
            exit(1)


    def _compile_standard_json(self):
        FNULL = open(os.devnull, 'w')
        cmd = "cat %s" % self.source
        p1 = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
        cmd = "solc --allow-paths %s --standard-json" % self.allow_paths
        p2 = subprocess.Popen(shlex.split(cmd), stdin=p1.stdout, stdout=subprocess.PIPE, stderr=FNULL)
        p1.stdout.close()
        out = p2.communicate()[0]
        with open('standard_json_output', 'w') as of:
            of.write(out)

        return self._compile_standard_json_output('standard_json_output')

    def _compile_standard_json_output(self, json_output_file):
        with open(json_output_file, 'r') as f:
            out = f.read()
        j = json.loads(out)
        contracts = []
        for source in j['sources']:
            for contract in j['contracts'][source]:
                cname = source + ":" + contract
                evm = j['contracts'][source][contract]['evm']['deployedBytecode']['object']
                contracts.append((cname, evm))
        return contracts

    def _removeSwarmHash(self, evm):
        evm_without_hash = re.sub(r"a165627a7a72305820\S{64}0029$", "", evm)
        return evm_without_hash

    def _link_libraries(self, filename, libs):
        options = []
        for idx, lib in enumerate(libs):
            lib_address = "0x" + hex(idx+1)[2:].zfill(40)
            options.append("--libraries %s:%s" % (lib, lib_address))
        if self.allow_paths:
            options.append(F"--allow-paths {self.allow_paths}")
        com = CryticCompile(target=self.source, solc_args=' '.join(options), solc_remaps=self.remap)

        return self._extract_bin_obj(com)

    def _prepare_disasm_files_for_analysis(self, contracts):
        for contract, bytecode in contracts:
            self._prepare_disasm_file(contract, bytecode)

    def _prepare_disasm_file(self, target, bytecode):
        self._write_evm_file(target, bytecode)
        self._write_disasm_file(target)

    def _get_temporary_files(self, target):
        return {
            "evm": target + ".evm",
            "disasm": target + ".evm.disasm",
            "log": target + ".evm.disasm.log"
        }

    def _write_evm_file(self, target, bytecode):
        evm_file = self._get_temporary_files(target)["evm"]
        with open(evm_file, 'w') as of:
            of.write(self._removeSwarmHash(bytecode))


    def _write_disasm_file(self, target):
        tmp_files = self._get_temporary_files(target)
        evm_file = tmp_files["evm"]
        disasm_file = tmp_files["disasm"]
        disasm_out = ""

        try:
            with open(evm_file, 'r') as f:
                bytecode = f.read().strip()

            # Remove the 0x prefix, because evm disasm expects only the bytecode.
            if bytecode.startswith("0x"):
                bytecode = bytecode[2:]

            # First we check for the disassembler we want to use, then we parse the output to 
            # match the output of the evm disasm command, because it was previously used.
            # "evm disasm" prints the address in 5 hex digits, followed by the instruction name.
            # If the instruction has push data, it is printed after the instruction name.
            # We want to keep that format, while using pyevmasm's or evmdasm's disassembly functions.
            if self.disassembler == "pyevmasm":         
                instructions = disassemble_hex(bytecode)
                i = 0
                for instr in instructions.splitlines():
                    disasm_out += f"{i:05x}: {instr}\n"
                    
                    # With pyevmasm, we need to construct the index, because the disassembler doesn't
                    # do it for us.
                    # If the instruction is a PUSH, we need to add the length of the data to the index.
                    # otherwise, we just add 1 to the index.
                    if instr.startswith("PUSH"):
                        i += 1 + int(instr.split()[0][4:])
                    else:
                        i += 1

            elif self.disassembler == "evmdasm":
                
                instructions = EvmBytecode(bytecode).disassemble()
                for instr in instructions:
                    line = f"{instr.address:05x}: {instr.name}"
                    if hasattr(instr, "operand") and instr.operand:
                        line += f" 0x{instr.operand}"
                    disasm_out += line + "\n"
                
                # evmdasm is to old to understand some newer opcodes, so we need to replace the UNKNOWN
                # opcodes with the known ones.
                disasm_out = disasm_out.replace("BREAKPOINT", "CREATE2")
                disasm_out = disasm_out.replace("SSIZE", "STATICCALL")
                disasm_out = disasm_out.replace("SUICIDE", "SELFDESTRUCT")
                disasm_out = disasm_out.replace("UNKNOWN_0x49", "BLOBHASH")
                disasm_out = disasm_out.replace("UNKNOWN_0x4a", "BLOBBASEFEE")
                disasm_out = disasm_out.replace("UNKNOWN_0x5c", "TLOAD")
                disasm_out = disasm_out.replace("UNKNOWN_0x5d", "TSTORE")
                disasm_out = disasm_out.replace("UNKNOWN_0xfe", "INVALID")
            else:
                raise ValueError("Unknown disassembler: %s" % self.disassembler)

            logging.debug("Raw instructions: %s", instructions)

        except Exception as e:
            logging.critical("Disassembly failed: %s", e)
            exit()

        with open(disasm_file, 'w') as of:
            of.write(disasm_out)

    def _rm_tmp_files_of_multiple_contracts(self, contracts):
        if self.input_type in ['standard_json', 'standard_json_output']:
            self._rm_file('standard_json_output')
        for contract, _ in contracts:
            self._rm_tmp_files(contract)

    def _rm_tmp_files(self, target):
        tmp_files = self._get_temporary_files(target)
        if not self.evm:
            self._rm_file(tmp_files["evm"])
            self._rm_file(tmp_files["disasm"])
        self._rm_file(tmp_files["log"])

    def _rm_file(self, path):
        if os.path.isfile(path):
            os.unlink(path)
