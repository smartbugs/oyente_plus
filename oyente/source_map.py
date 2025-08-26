# type: ignore
import ast
import json
from typing import Any
from typing import ClassVar
from typing import Dict
from typing import List
from typing import Optional

from ast_helper import AstHelper
from utils import run_command
from utils import run_command_with_err


class Source:
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.content = self._load_content()
        self.line_break_positions = self._load_line_break_positions()

    def _load_content(self) -> str:
        with open(self.filename, "rb") as f:
            content = f.read().decode("UTF-8")
        return content

    def _load_line_break_positions(self) -> List[int]:
        return [i for i, letter in enumerate(self.content) if letter == "\n"]


class SourceMap:
    parent_filename: ClassVar[str] = ""
    position_groups: ClassVar[Dict[str, Any]] = {}
    sources: ClassVar[Dict[str, Any]] = {}
    ast_helper: ClassVar[Optional[Any]] = None
    func_to_sig_by_contract: ClassVar[Dict[str, Any]] = {}
    remap: ClassVar[str] = ""
    allow_paths: ClassVar[str] = ""

    def __init__(
        self,
        cname: str,
        parent_filename: str,
        input_type: str,
        root_path: str = "",
        remap: str = "",
        allow_paths: str = "",
    ) -> None:
        self.root_path = root_path
        self.cname = cname
        self.input_type = input_type
        self.parent_filename = parent_filename
        if not SourceMap.parent_filename:
            SourceMap.remap = remap
            SourceMap.allow_paths = allow_paths
            SourceMap.parent_filename = parent_filename
            if input_type == "solidity":
                SourceMap.position_groups = SourceMap._load_position_groups()
            elif input_type == "standard json":
                SourceMap.position_groups = SourceMap._load_position_groups_standard_json()
            else:
                raise Exception("There is no such type of input")
            SourceMap.ast_helper = AstHelper(
                SourceMap.parent_filename, input_type, SourceMap.remap, SourceMap.allow_paths
            )
            SourceMap.func_to_sig_by_contract = SourceMap._get_sig_to_func_by_contract()
        self.source = self._get_source()  # type: ignore[assignment]
        self.positions = self._get_positions()  # type: ignore[assignment]
        self.instr_positions: Dict[Any, Any] = {}
        self.var_names = self._get_var_names()  # type: ignore[assignment]
        self.func_call_names = self._get_func_call_names()  # type: ignore[assignment]
        self.callee_src_pairs = self._get_callee_src_pairs()  # type: ignore[assignment]
        self.func_name_to_params = self._get_func_name_to_params()  # type: ignore[assignment]
        self.sig_to_func = self._get_sig_to_func()  # type: ignore[assignment]

    def get_source_code(self, pc: Any) -> str:
        try:
            pos = self.instr_positions[pc]
        except KeyError:
            return ""
        begin = pos["begin"]
        end = pos["end"]
        return self.source.content[begin:end]

    def get_source_code_from_src(self, src):
        src = src.split(":")
        start = int(src[0])
        end = start + int(src[1])
        return self.source.content[start:end]

    def get_buggy_line(self, pc):
        try:
            pos = self.instr_positions[pc]
        except KeyError:
            return ""
        location = self.get_location(pc)
        # Guard against 'begin' or 'line' being None.
        # This is possible since the new AST format introduced in Solidity 0.5.x
        if not location or location.get("line") is None:
            return ""  # no location, so no buggy line
        begin = self.source.line_break_positions[location["begin"]["line"] - 1] + 1
        end = pos["end"]
        return self.source.content[begin:end]

    def get_buggy_line_from_src(self, src):
        pos = self._convert_src_to_pos(src)
        location = self.get_location_from_src(src)
        begin = self.source.line_break_positions[location["begin"]["line"] - 1] + 1
        end = pos["end"]
        return self.source.content[begin:end]

    def get_location(self, pc):
        pos = self.instr_positions[pc]
        return self._convert_offset_to_line_column(pos)

    def get_location_from_src(self, src):
        pos = self._convert_src_to_pos(src)
        return self._convert_offset_to_line_column(pos)

    def get_parameter_or_state_var(self, var_name):
        try:
            names = [node.id for node in ast.walk(ast.parse(var_name)) if isinstance(node, ast.Name)]
            if names[0] in self.var_names:
                return var_name
        except (IndexError, AttributeError, SyntaxError):
            return None
        return None

    def _convert_src_to_pos(self, src):
        """Convert source mapping string to position dictionary.

        Args:
            src: Source mapping string in format "start:length:file_id"

        Returns:
            Dictionary with begin and end positions, or safe defaults if parsing fails
        """
        try:
            src = src.split(":")
            if len(src) != 3:  # Expect exactly 3 parts: start:length:file_id
                return {"begin": 0, "end": 0}
            pos = {}
            pos["begin"] = int(src[0])
            length = int(src[1])
            pos["end"] = pos["begin"] + length - 1
            return pos
        except (ValueError, IndexError):
            return {"begin": 0, "end": 0}

    def _get_sig_to_func(self) -> Dict[str, str]:
        """Get mapping from function signature hashes to function names.

        Uses safe dictionary access to prevent KeyError when contract name
        doesn't exist or has no 'hashes' key.

        Returns:
            Dictionary mapping function signature hashes to function names.
            Returns empty dict if contract data or hashes are missing.
        """
        contract_data = SourceMap.func_to_sig_by_contract.get(self.cname, {})
        func_to_sig = contract_data.get("hashes", {})
        return {sig: func for func, sig in func_to_sig.items()}

    def _get_func_name_to_params(self):
        func_name_to_params = SourceMap.ast_helper.get_func_name_to_params(self.cname)
        for func_name in func_name_to_params:
            calldataload_position = 0
            for param in func_name_to_params[func_name]:
                if param["type"] == "ArrayTypeName":
                    param["position"] = calldataload_position
                    calldataload_position += param["value"]
                else:
                    param["position"] = calldataload_position
                    calldataload_position += 1
        return func_name_to_params

    def _get_source(self):
        fname = self.get_filename()
        if fname not in SourceMap.sources:
            SourceMap.sources[fname] = Source(fname)
        return SourceMap.sources[fname]

    def _get_callee_src_pairs(self):
        return SourceMap.ast_helper.get_callee_src_pairs(self.cname)

    def _get_var_names(self):
        return SourceMap.ast_helper.extract_state_variable_names(self.cname)

    def _get_func_call_names(self):
        func_call_srcs = SourceMap.ast_helper.extract_func_call_srcs(self.cname)
        func_call_names = []
        for src in func_call_srcs:
            src = src.split(":")
            start = int(src[0])
            end = start + int(src[1])
            func_call_names.append(self.source.content[start:end])
        return func_call_names

    @classmethod
    def _get_solc_version(cls) -> tuple[int, int, int]:
        """Get the current solc version as a tuple (major, minor, patch)."""
        try:
            out, err = run_command_with_err("solc --version")
            if err or not out:
                raise RuntimeError(f"Failed to get solc version: {err}")

            # Parse version from output like "solc, the solidity compiler commandline interface\nVersion: 0.4.11+..."
            for line in out.split("\n"):
                if line.startswith("Version:"):
                    version_str = line.split(":")[1].strip()
                    # Extract version numbers before '+' or other suffixes
                    version_numbers = version_str.split("+")[0].strip()
                    parts = version_numbers.split(".")
                    if len(parts) >= 3:
                        return (int(parts[0]), int(parts[1]), int(parts[2]))

            raise RuntimeError(f"Could not parse solc version from: {out}")
        except Exception as e:
            raise RuntimeError(f"Error detecting solc version: {e}") from e

    @classmethod
    def _build_combined_json_cmd(cls, json_flags: str) -> str:
        """Build solc combined-json command with version-aware flag support."""
        try:
            major, minor, _ = cls._get_solc_version()

            # The 'hashes' flag was introduced in solc 0.6.0
            if (major, minor) >= (0, 6) and "hashes" in json_flags:
                # Use hashes flag for newer versions
                flags = json_flags
            elif "hashes" in json_flags:
                # Fall back to available flags for older versions
                # Use 'abi' as a basic alternative that's widely supported
                flags = json_flags.replace("hashes", "abi")
            else:
                flags = json_flags

            if cls.allow_paths:
                return f"solc --combined-json {flags} {cls.remap} {cls.parent_filename} --allow-paths {cls.allow_paths}"
            else:
                return f"solc --combined-json {flags} {cls.remap} {cls.parent_filename}"

        except Exception:
            # Fallback to basic command if version detection fails
            if cls.allow_paths:
                return f"solc --combined-json abi {cls.remap} {cls.parent_filename} --allow-paths {cls.allow_paths}"
            else:
                return f"solc --combined-json abi {cls.remap} {cls.parent_filename}"

    @classmethod
    def _get_sig_to_func_by_contract(cls):
        cmd = cls._build_combined_json_cmd("hashes")
        out = run_command(cmd)

        # Validate output before parsing JSON
        if not out or out.strip() == "":
            raise RuntimeError(
                f"Solidity compilation failed. Command '{cmd}' produced empty output. "
                f"This may be due to compilation errors or unsupported compiler flags."
            )

        try:
            out = json.loads(out)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse solc output as JSON: {e}. Command was: {cmd}") from e

        if "contracts" not in out:
            raise RuntimeError(f"Solc output does not contain 'contracts' key. Available keys: {list(out.keys())}")

        return out["contracts"]

    @classmethod
    def _load_position_groups_standard_json(cls):
        with open("standard_json_output") as f:
            output = f.read()
        output = json.loads(output)
        return output["contracts"]

    @classmethod
    def _load_position_groups(cls):
        if cls.allow_paths:
            cmd = f"solc --combined-json asm {cls.remap} {cls.parent_filename} --allow-paths {cls.allow_paths}"
        else:
            cmd = f"solc --combined-json asm {cls.remap} {cls.parent_filename}"
        out = run_command(cmd)
        out = json.loads(out)
        return out["contracts"]

    def _get_positions(self):
        if self.input_type == "solidity":
            asm = SourceMap.position_groups[self.cname]["asm"][".data"]["0"]
        else:
            filename, contract_name = self.cname.split(":")
            asm = SourceMap.position_groups[filename][contract_name]["evm"]["legacyAssembly"][".data"]["0"]
        positions = asm[".code"]
        while True:
            try:
                positions.append(None)
                positions += asm[".data"]["0"][".code"]
                asm = asm[".data"]["0"]
            except (KeyError, TypeError):
                break
        return positions

    def _convert_offset_to_line_column(self, pos):
        ret = {}
        ret["begin"] = None
        ret["end"] = None
        if pos["begin"] >= 0 and (pos["end"] - pos["begin"] + 1) >= 0:
            ret["begin"] = self._convert_from_char_pos(pos["begin"])
            ret["end"] = self._convert_from_char_pos(pos["end"])
        return ret

    def _convert_from_char_pos(self, pos):
        line = self._find_lower_bound(pos, self.source.line_break_positions)
        if self.source.line_break_positions[line] != pos:
            line += 1
        begin_col = 0 if line == 0 else self.source.line_break_positions[line - 1] + 1
        col = pos - begin_col
        return {"line": line, "column": col}

    def _find_lower_bound(self, target, array):
        start = 0
        length = len(array)
        while length > 0:
            half = length >> 1
            middle = start + half
            if array[middle] <= target:
                length = length - 1 - half
                start = middle + 1
            else:
                length = half
        return start - 1

    def get_filename(self):
        """Get the full filename path.

        Returns:
            The full path to the source file, constructed from root_path and parent_filename.
            For standard JSON input, uses the contract name as the file path.
        """
        if self.input_type == "standard json":
            return self.cname.split(":")[0]
        else:
            # For Solidity input, construct the full path
            if self.root_path:
                import os.path

                return os.path.join(self.root_path, self.parent_filename)
            else:
                return self.parent_filename
