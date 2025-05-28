import logging
from utils import run_command
from ast_walker import AstWalker
import json
import copy
from typing import Any, Dict, List

class AstHelper:
    def __init__(self, filename, input_type, remap, allow_paths=""):
        self.input_type = input_type
        self.allow_paths = allow_paths
        if input_type == "solidity":
            self.remap = remap
            self.source_list = self.get_source_list(filename)
        elif input_type == "standard json":
            self.source_list = self.get_source_list_standard_json(filename)
        else:
            raise Exception("There is no such type of input")
        self.contracts = self.extract_contract_definitions(self.source_list)

    def get_source_list_standard_json(self, filename):
        with open('standard_json_output', 'r') as f:
            out = f.read()
        out = json.loads(out)
        return out["sources"]

    def get_source_list(self, filename):
        if self.allow_paths:
            cmd = "solc --combined-json ast %s %s --allow-paths %s" % (self.remap, filename, self.allow_paths)
        else:
            cmd = "solc --combined-json ast %s %s" % (self.remap, filename)
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
        if any(
            isinstance(e.get("AST"), dict) and "nodeType" in e["AST"]
            for e in out.get("sources", {}).values()
        ):
            out = self._semi_convert_new_to_old_ast_format(out)

        normalized = {
            path: {"AST": entry["AST"]}
            for path, entry in out["sources"].items()
        }
        return normalized

    def extract_contract_definitions(self, sourcesList):
        ret = {
            "contractsById": {},
            "contractsByName": {},
            "sourcesByContract": {}
        }
        walker = AstWalker()
        for k in sourcesList:
            if self.input_type == "solidity":
                ast = sourcesList[k]["AST"]
            else:
                ast = sourcesList[k]["legacyAST"]
            nodes = []
            walker.walk(ast, {"name": "ContractDefinition"}, nodes)
            for node in nodes:
                ret["contractsById"][node["id"]] = node
                ret["sourcesByContract"][node["id"]] = k
                ret["contractsByName"][k + ':' + node["attributes"]["name"]] = node
        return ret

    def get_linearized_base_contracts(self, id, contractsById):
        return map(lambda id: contractsById[id], contractsById[id]["attributes"]["linearizedBaseContracts"])

    def extract_state_definitions(self, c_name):
        node = self.contracts["contractsByName"][c_name]
        state_vars = []
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

    def extract_states_definitions(self):
        ret = {}
        for contract in self.contracts["contractsById"]:
            name = self.contracts["contractsById"][contract]["attributes"]["name"]
            source = self.contracts["sourcesByContract"][contract]
            full_name = source + ":" + name
            ret[full_name] = self.extract_state_definitions(full_name)
        return ret

    def extract_func_call_definitions(self, c_name):
        node = self.contracts["contractsByName"][c_name]
        walker = AstWalker()
        nodes = []
        if node:
            walker.walk(node, {"name":  "FunctionCall"}, nodes)
        return nodes

    def extract_func_calls_definitions(self):
        ret = {}
        for contract in self.contracts["contractsById"]:
            name = self.contracts["contractsById"][contract]["attributes"]["name"]
            source = self.contracts["sourcesByContract"][contract]
            full_name = source + ":" + name
            ret[full_name] = self.extract_func_call_definitions(full_name)
        return ret

    def extract_state_variable_names(self, c_name):
        state_variables = self.extract_states_definitions()[c_name]
        var_names = []
        for var_name in state_variables:
            var_names.append(var_name["attributes"]["name"])
        return var_names

    def extract_func_call_srcs(self, c_name):
        func_calls = self.extract_func_calls_definitions()[c_name]
        func_call_srcs = []
        for func_call in func_calls:
            func_call_srcs.append(func_call["src"])
        return func_call_srcs

    def get_callee_src_pairs(self, c_name):
        node = self.contracts["contractsByName"][c_name]
        walker = AstWalker()
        nodes = []
        if node:
            list_of_attributes = [
                {"attributes": {"member_name": "delegatecall"}},
                {"attributes": {"member_name": "call"}},
                {"attributes": {"member_name": "callcode"}}
            ]
            walker.walk(node, list_of_attributes, nodes)

        callee_src_pairs = []
        for node in nodes:
            if "children" in node and node["children"]:
                type_of_first_child = node["children"][0]["attributes"]["type"]
                if type_of_first_child.split(" ")[0] == "contract":
                    contract = type_of_first_child.split(" ")[1]
                    contract_path = self._find_contract_path(self.contracts["contractsByName"].keys(), contract)
                    callee_src_pairs.append((contract_path, node["src"]))
        return callee_src_pairs

    def get_func_name_to_params(self, c_name):
        node = self.contracts['contractsByName'][c_name]
        walker = AstWalker()
        func_def_nodes = []
        if node:
            walker.walk(node, {'name': 'FunctionDefinition'}, func_def_nodes)

        func_name_to_params = {}
        for func_def_node in func_def_nodes:
            func_name = func_def_node['attributes']['name']
            params_nodes = []
            walker.walk(func_def_node, {'name': 'ParameterList'}, params_nodes)

            params_node = params_nodes[0]
            param_nodes = []
            walker.walk(params_node, {'name': 'VariableDeclaration'}, param_nodes)

            for param_node in param_nodes:
                var_name = param_node['attributes']['name']
                type_name = param_node['children'][0]['name']
                if type_name == 'ArrayTypeName':
                    literal_nodes = []
                    walker.walk(param_node, {'name': 'Literal'}, literal_nodes)
                    if literal_nodes:
                        array_size = int(literal_nodes[0]['attributes']['value'])
                    else:
                        array_size = 1
                    param = {'name': var_name, 'type': type_name, 'value': array_size}
                elif type_name == 'ElementaryTypeName':
                    param = {'name': var_name, 'type': type_name}
                else:
                    param = {'name': var_name, 'type': type_name}

                if func_name not in func_name_to_params:
                    func_name_to_params[func_name] = [param]
                else:
                    func_name_to_params[func_name].append(param)
        return func_name_to_params

    def _find_contract_path(self, contract_paths, contract):
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
        
        # Normally this would be a fully defined function, but it is only used
        # here, so using a lamda object is fine.
        is_node = lambda obj: (isinstance(obj, dict) and "nodeType" in obj)

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

            if ntype in {"ElementaryTypeName", "UserDefinedTypeName",
                        "ArrayTypeName", "Mapping"}:
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
