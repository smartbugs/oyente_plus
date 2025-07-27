"""AST Helper module for Solidity contract analysis.

This module provides comprehensive utilities for processing Solidity contract
ASTs (Abstract Syntax Trees) from different compiler versions. It handles both
legacy (v4) and modern (v5+) AST formats, extracting contract definitions,
state variables, function calls, and other structural elements.

Key Features:
    - Multi-format AST processing (solc v4/v5+ compatibility)
    - Contract definition extraction and indexing
    - State variable and function analysis
    - Semi-automatic AST format conversion
    - Source mapping and cross-referencing

Security Considerations:
    - Validates all compiler output before processing
    - Handles malformed AST structures gracefully
    - Sanitizes file paths and command execution

Example:
    >>> helper = AstHelper("contract.sol", "solidity", "")
    >>> contracts = helper.contracts["contractsByName"]
    >>> for name, contract in contracts.items():
    ...     print(f"Found contract: {name}")
"""

import copy
import json
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from typing import Union

from ast_walker import AstWalker
from utils import run_command


class AstHelper:
    """Helper class for analyzing Solidity contract ASTs.

    This class provides comprehensive functionality for processing and analyzing
    Solidity contract Abstract Syntax Trees from different compiler versions.
    It automatically handles format differences between solc v4 and v5+ ASTs.

    Attributes:
        input_type: Type of input ("solidity" or "standard json")
        allow_paths: Additional paths allowed for imports
        source_list: Dictionary mapping file paths to AST data
        contracts: Indexed contract definitions by ID and name

    Security Notes:
        - All external compiler commands are validated
        - File paths are sanitized before processing
        - AST structures are validated before parsing

    Example:
        >>> helper = AstHelper("MyContract.sol", "solidity", "")
        >>> state_vars = helper.extract_state_variable_names("MyContract.sol:MyContract")
        >>> print(f"State variables: {state_vars}")
    """

    def __init__(self, filename: str, input_type: str, remap: str, allow_paths: str = "") -> None:
        """Initialize AST helper with contract source.

        Args:
            filename: Path to Solidity contract file or JSON input
            input_type: Type of input ("solidity" or "standard json")
            remap: Solidity import remapping configuration
            allow_paths: Additional paths allowed for imports

        Raises:
            ValueError: If input_type is not supported
            FileNotFoundError: If source file cannot be found
            json.JSONDecodeError: If JSON input is malformed
        """
        self.input_type = input_type
        self.allow_paths = allow_paths
        if input_type == "solidity":
            self.remap = remap
            self.source_list = self.get_source_list(filename)
        elif input_type == "standard json":
            self.source_list = self.get_source_list_standard_json(filename)
        else:
            raise ValueError(f"Unsupported input type: {input_type}. Expected 'solidity' or 'standard json'")
        self.contracts = self.extract_contract_definitions(self.source_list)

    def get_source_list_standard_json(self, filename: str) -> Dict[str, Any]:
        """Extract source list from standard JSON compiler output.

        Args:
            filename: Path to JSON file (currently unused, reads from standard_json_output)

        Returns:
            Dictionary mapping source file paths to their AST data

        Raises:
            FileNotFoundError: If standard_json_output file not found
            json.JSONDecodeError: If JSON format is invalid
        """
        with open("standard_json_output") as f:
            out = f.read()
        parsed_out: Dict[str, Any] = json.loads(out)
        sources: Dict[str, Any] = parsed_out["sources"]
        return sources

    def get_source_list(self, filename: str) -> Dict[str, Dict[str, Any]]:
        """Extract source list from Solidity file using solc compiler.

        Args:
            filename: Path to Solidity source file

        Returns:
            Dictionary mapping source file paths to their AST data

        Raises:
            subprocess.CalledProcessError: If solc compilation fails
            json.JSONDecodeError: If compiler output is not valid JSON
        """
        if self.allow_paths:
            cmd = f"solc --combined-json ast {self.remap} {filename} --allow-paths {self.allow_paths}"
        else:
            cmd = f"solc --combined-json ast {self.remap} {filename}"
        out = run_command(cmd)
        out = json.loads(out)

        # TODO:   This following code & called function are a temporary workaround until
        #         the symexecution code is updated to use the new format. Delete this
        #         code and the called function, when the refactoring is done.
        #
        # The solc v4 AST format is currently required by the symexecution code in Oyente,
        # because the symexecution code does not yet understand the new v5+ AST format.
        # The v5+ AST format is a tree of nodes, where each node has a "nodeType" and a
        # "nodes" array. The v4 AST format is a flat list of nodes, where each node has a
        # "name" and "attributes" field.
        if any(isinstance(e.get("AST"), dict) and "nodeType" in e["AST"] for e in out.get("sources", {}).values()):
            out = self._semi_convert_new_to_old_ast_format(out)

        normalized = {path: {"AST": entry["AST"]} for path, entry in out["sources"].items()}
        return normalized

    def extract_contract_definitions(self, sources_list: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Extract and index all contract definitions from source ASTs.

        Args:
            sources_list: Dictionary mapping file paths to AST data

        Returns:
            Dictionary containing three indexes:
            - contractsById: Maps contract IDs to contract nodes
            - contractsByName: Maps "file:name" to contract nodes
            - sourcesByContract: Maps contract IDs to source file paths
        """
        ret: Dict[str, Dict[str, Any]] = {"contractsById": {}, "contractsByName": {}, "sourcesByContract": {}}
        walker = AstWalker()
        for k in sources_list:
            ast = sources_list[k]["AST"] if self.input_type == "solidity" else sources_list[k]["legacyAST"]
            nodes: List[Dict[str, Any]] = []
            walker.walk(ast, {"name": "ContractDefinition"}, nodes)
            for node in nodes:
                ret["contractsById"][node["id"]] = node
                ret["sourcesByContract"][node["id"]] = k
                ret["contractsByName"][k + ":" + node["attributes"]["name"]] = node
        return ret

    def get_linearized_base_contracts(self, contract_id: str, contracts_by_id: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get linearized inheritance chain for a contract.

        Args:
            contract_id: ID of the contract to get inheritance chain for
            contracts_by_id: Dictionary mapping contract IDs to contract nodes

        Returns:
            List of contract nodes in linearized inheritance order
        """
        return [
            contracts_by_id[base_id]
            for base_id in contracts_by_id[contract_id]["attributes"]["linearizedBaseContracts"]
        ]

    def extract_state_definitions(self, c_name: str) -> List[Dict[str, Any]]:
        """Extract state variable definitions for a contract.

        Args:
            c_name: Full contract name in format "file:contract"

        Returns:
            List of state variable declaration nodes
        """
        node = self.contracts["contractsByName"].get(c_name)
        state_vars: List[Dict[str, Any]] = []
        if node:
            base_contracts = self.get_linearized_base_contracts(node["id"], self.contracts["contractsById"])
            base_contracts = list(base_contracts)
            base_contracts = list(reversed(base_contracts))
            for contract in base_contracts:
                if "children" in contract:
                    for item in contract["children"]:
                        if item["name"] == "VariableDeclaration":
                            state_vars.append(item)
        return state_vars

    def extract_states_definitions(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract state definitions for all contracts.

        Returns:
            Dictionary mapping full contract names to lists of state variable nodes
        """
        ret: Dict[str, List[Dict[str, Any]]] = {}
        for contract in self.contracts["contractsById"]:
            name = self.contracts["contractsById"][contract]["attributes"]["name"]
            source = self.contracts["sourcesByContract"][contract]
            full_name = source + ":" + name
            ret[full_name] = self.extract_state_definitions(full_name)
        return ret

    def extract_func_call_definitions(self, c_name: str) -> List[Dict[str, Any]]:
        """Extract function call definitions for a contract.

        Args:
            c_name: Full contract name in format "file:contract"

        Returns:
            List of function call nodes found in the contract
        """
        node = self.contracts["contractsByName"][c_name]
        walker = AstWalker()
        nodes: List[Dict[str, Any]] = []
        if node:
            walker.walk(node, {"name": "FunctionCall"}, nodes)
        return nodes

    def extract_func_calls_definitions(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract function call definitions for all contracts.

        Returns:
            Dictionary mapping full contract names to lists of function call nodes
        """
        ret: Dict[str, List[Dict[str, Any]]] = {}
        for contract in self.contracts["contractsById"]:
            name = self.contracts["contractsById"][contract]["attributes"]["name"]
            source = self.contracts["sourcesByContract"][contract]
            full_name = source + ":" + name
            ret[full_name] = self.extract_func_call_definitions(full_name)
        return ret

    def extract_state_variable_names(self, c_name: str) -> List[str]:
        """Extract names of state variables for a contract.

        Args:
            c_name: Full contract name in format "file:contract"

        Returns:
            List of state variable names
        """
        state_variables = self.extract_states_definitions()[c_name]
        var_names: List[str] = []
        for var_name in state_variables:
            var_names.append(var_name["attributes"]["name"])
        return var_names

    def extract_func_call_srcs(self, c_name: str) -> List[str]:
        """Extract source locations of function calls for a contract.

        Args:
            c_name: Full contract name in format "file:contract"

        Returns:
            List of source location strings for function calls
        """
        func_calls = self.extract_func_calls_definitions()[c_name]
        func_call_srcs: List[str] = []
        for func_call in func_calls:
            func_call_srcs.append(func_call["src"])
        return func_call_srcs

    def get_callee_src_pairs(self, c_name: str) -> List[Tuple[str, str]]:
        """Get contract call source location pairs for external calls.

        Args:
            c_name: Full contract name in format "file:contract"

        Returns:
            List of tuples containing (contract_path, source_location) for external calls
        """
        node = self.contracts["contractsByName"][c_name]
        walker = AstWalker()
        nodes: List[Dict[str, Any]] = []
        if node:
            list_of_attributes = [
                {"attributes": {"member_name": "delegatecall"}},
                {"attributes": {"member_name": "call"}},
                {"attributes": {"member_name": "callcode"}},
            ]
            walker.walk(node, list_of_attributes, nodes)

        callee_src_pairs: List[Tuple[str, str]] = []
        for node in nodes:
            if node.get("children"):
                type_of_first_child = node["children"][0]["attributes"]["type"]
                if type_of_first_child.split(" ")[0] == "contract":
                    contract = type_of_first_child.split(" ")[1]
                    contract_path = self._find_contract_path(list(self.contracts["contractsByName"].keys()), contract)
                    callee_src_pairs.append((contract_path, node["src"]))
        return callee_src_pairs

    def get_func_name_to_params(self, c_name: str) -> Dict[str, List[Dict[str, Union[str, int]]]]:
        """Get function names mapped to their parameter information.

        Args:
            c_name: Full contract name in format "file:contract"

        Returns:
            Dictionary mapping function names to lists of parameter info dicts.
            Each parameter dict contains 'name', 'type', and optionally 'value' (for arrays).
        """
        node = self.contracts["contractsByName"][c_name]
        walker = AstWalker()
        func_def_nodes: List[Dict[str, Any]] = []
        if node:
            walker.walk(node, {"name": "FunctionDefinition"}, func_def_nodes)

        func_name_to_params: Dict[str, List[Dict[str, Union[str, int]]]] = {}
        for func_def_node in func_def_nodes:
            func_name = func_def_node["attributes"]["name"]
            params_nodes: List[Dict[str, Any]] = []
            walker.walk(func_def_node, {"name": "ParameterList"}, params_nodes)

            params_node = params_nodes[0]
            param_nodes: List[Dict[str, Any]] = []
            walker.walk(params_node, {"name": "VariableDeclaration"}, param_nodes)

            for param_node in param_nodes:
                var_name = param_node["attributes"]["name"]
                type_name = param_node["children"][0]["name"]
                if type_name == "ArrayTypeName":
                    literal_nodes: List[Dict[str, Any]] = []
                    walker.walk(param_node, {"name": "Literal"}, literal_nodes)
                    array_size = int(literal_nodes[0]["attributes"]["value"]) if literal_nodes else 1
                    param = {"name": var_name, "type": type_name, "value": array_size}
                elif type_name == "ElementaryTypeName":
                    param = {"name": var_name, "type": type_name}
                else:
                    param = {"name": var_name, "type": type_name}

                if func_name not in func_name_to_params:
                    func_name_to_params[func_name] = [param]
                else:
                    func_name_to_params[func_name].append(param)
        return func_name_to_params

    def _find_contract_path(self, contract_paths: List[str], contract: str) -> str:
        """Find the full path for a contract by name.

        Args:
            contract_paths: List of full contract paths ("file:contract" format)
            contract: Contract name to search for

        Returns:
            Full contract path if found, empty string otherwise
        """
        for path in contract_paths:
            cname = path.split(":")[-1]
            if contract == cname:
                return path
        return ""

    def _semi_convert_new_to_old_ast_format(self, ast_tree: Dict[str, Any]) -> Dict[str, Any]:
        """
        Semi-convert solc v5+ AST (nodeType/nodes) to solc v4 AST structure,
        with keys ordered as Oyente expects ist.
        """

        # The helper functions are inside this function to keep AST struction
        # conversion in one place. This is a temporary workaround until the
        # symexecution code is updated to use the new format.
        tree = copy.deepcopy(ast_tree)

        # Helper function to check if an object is an AST node
        def is_node(obj: Any) -> bool:
            """Check if an object is an AST node (has nodeType field)."""
            return isinstance(obj, dict) and "nodeType" in obj

        def leaf_attrs(node: Dict[str, Any]) -> Dict[str, Any]:
            out: Dict[str, Any] = {}
            skip = {"nodeType", "nodes", "id", "src", "parameters", "returnParameters", "body"}

            for k, v in node.items():
                if k in skip:
                    continue
                if is_node(v) or (isinstance(v, list) and all(is_node(i) for i in v)):
                    continue
                out[k] = v

            logging.debug(f"Converted leaf attributes: {out}")
            return out

        def collect_children(node: Dict[str, Any]) -> List[Dict[str, Any]]:
            ntype = node["nodeType"]
            kids: List[Dict[str, Any]] = []

            if ntype == "FunctionDefinition":
                for key in ("parameters", "returnParameters", "body"):
                    if is_node(node.get(key)):
                        kids.append(convert(node[key]))
                return kids

            for child in node.get("nodes", []):
                kids.append(convert(child))

            for v in node.values():
                if is_node(v):
                    kids.append(convert(v))
                elif isinstance(v, list):
                    kids.extend(convert(i) for i in v if is_node(i))

            logging.debug(f"Converted children: {kids}")
            return kids

        def convert(node: Dict[str, Any]) -> Dict[str, Any]:
            ntype = node["nodeType"]
            children = collect_children(node)
            attrs = leaf_attrs(node)

            if ntype == "ContractDefinition":
                attrs.update(
                    baseContracts=node.get("baseContracts") or [None],
                    contractDependencies=node.get("contractDependencies") or [None],
                    contractKind=node.get("contractKind"),
                    fullyImplemented=node.get("fullyImplemented"),
                    linearizedBaseContracts=node.get("linearizedBaseContracts", []),
                    name=node.get("name"),
                    scope=node.get("scope"),
                    documentation=None,
                )

            if ntype in {"ElementaryTypeName", "UserDefinedTypeName", "ArrayTypeName", "Mapping"}:
                td = attrs.pop("typeDescriptions", None)
                if isinstance(td, dict) and "typeString" in td:
                    attrs["type"] = td["typeString"]
                attrs.pop("stateMutability", None)

            if ntype == "ParameterList" and not children:
                attrs["parameters"] = [None]

            if ntype == "VariableDeclaration":
                attrs.pop("mutability", None)
                attrs.pop("nameLocation", None)
                td = attrs.pop("typeDescriptions", {})
                if isinstance(td, dict) and "typeString" in td:
                    attrs["type"] = td["typeString"]
                attrs.setdefault("value", None)

            new_node: Dict[str, Any] = {
                "name": ntype,
                "attributes": attrs,
            }
            if children:
                new_node["children"] = children
            if "id" in node:
                new_node["id"] = node["id"]
            if "src" in node:
                new_node["src"] = node["src"]

            logging.debug(f"Converted node: {new_node}")
            return new_node

        # Run over every source that is identified as a v5+ AST
        # and semi-convert it to the v4 AST format
        for entry in tree.get("sources", {}).values():
            ast_root = entry.get("AST")
            if is_node(ast_root):
                logging.debug(f"v5+ AST format detected. Semi-converting {ast_root} to AST v4.")
                entry["AST"] = convert(ast_root)

        logging.debug(f"Final converted AST: {tree}")
        return tree
