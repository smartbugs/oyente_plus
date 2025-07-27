"""Unit tests for ast_helper module.

This module contains comprehensive unit tests for the AstHelper class,
testing Solidity AST processing, contract analysis, and various extraction
utilities.

Test Coverage:
    - AstHelper initialization with different input types
    - Source list extraction from Solidity and JSON
    - Contract definition extraction and indexing
    - State variable and function analysis
    - AST format conversion (v4/v5+ compatibility)
    - Edge cases and error handling
"""

import json
from typing import Any
from typing import Dict
from unittest.mock import Mock
from unittest.mock import patch

import pytest


# Create a mock AstWalker that simulates contract extraction
def mock_walk(ast, attributes, nodes):
    """Mock AstWalker.walk method that finds nodes by name or attributes."""

    # Handle both single attribute dict and list of attributes
    if isinstance(attributes, list):
        # For list of attributes, check each one
        for attr_dict in attributes:
            if "attributes" in attr_dict and "member_name" in attr_dict["attributes"]:
                target_member = attr_dict["attributes"]["member_name"]

                # Find nodes with matching member_name
                def find_member_nodes(node, member=target_member):
                    if isinstance(node, dict):
                        if (
                            node.get("name") == "MemberAccess"
                            and node.get("attributes", {}).get("member_name") == member
                        ):
                            nodes.append(node)
                        # Recursively search children
                        children = node.get("children", [])
                        for child in children:
                            find_member_nodes(child, member)

                find_member_nodes(ast)
    else:
        # Handle single attribute dict (original behavior)
        target_name = attributes.get("name")
        if target_name:
            # Find nodes with the specified name and add them to nodes
            def find_nodes(node):
                if isinstance(node, dict):
                    if node.get("name") == target_name:
                        nodes.append(node)
                    # Recursively search children
                    children = node.get("children", [])
                    for child in children:
                        find_nodes(child)

            find_nodes(ast)


# Create persistent mocks
utils_mock = Mock(run_command=Mock(return_value=""))
mock_walker_instance = Mock()
mock_walker_instance.walk = Mock(side_effect=mock_walk)
ast_walker_mock = Mock(AstWalker=Mock(return_value=mock_walker_instance))

# Mock dependencies before importing AstHelper
with patch.dict(
    "sys.modules",
    {
        "utils": utils_mock,
        "ast_walker": ast_walker_mock,
    },
):
    from oyente.ast_helper import AstHelper


class TestAstHelper:
    """Test cases for AstHelper class."""

    @pytest.fixture
    def mock_solidity_ast(self) -> Dict[str, Any]:
        """Create mock Solidity AST structure."""
        return {
            "sources": {
                "test.sol": {
                    "AST": {
                        "name": "SourceUnit",
                        "children": [
                            {
                                "name": "ContractDefinition",
                                "id": "1",
                                "attributes": {"name": "TestContract", "linearizedBaseContracts": ["1"]},
                                "children": [
                                    {"name": "VariableDeclaration", "id": "2", "attributes": {"name": "owner"}},
                                    {"name": "FunctionDefinition", "id": "3", "attributes": {"name": "transfer"}},
                                ],
                            }
                        ],
                    }
                }
            }
        }

    @pytest.fixture
    def mock_v5_ast(self) -> Dict[str, Any]:
        """Create mock Solidity v5+ AST structure."""
        return {
            "sources": {
                "test.sol": {
                    "AST": {
                        "nodeType": "SourceUnit",
                        "nodes": [
                            {
                                "nodeType": "ContractDefinition",
                                "id": 1,
                                "name": "TestContract",
                                "linearizedBaseContracts": [1],
                                "nodes": [{"nodeType": "VariableDeclaration", "id": 2, "name": "owner"}],
                            }
                        ],
                    }
                }
            }
        }

    @pytest.fixture
    def mock_standard_json(self) -> Dict[str, Any]:
        """Create mock standard JSON output."""
        return {
            "sources": {
                "test.sol": {
                    "legacyAST": {
                        "name": "SourceUnit",
                        "children": [{"name": "ContractDefinition", "id": "1", "attributes": {"name": "TestContract"}}],
                    }
                }
            }
        }

    def test_init_solidity_input_type(self, mock_solidity_ast):
        """Test AstHelper initialization with Solidity input type."""
        # Configure the persistent mock to return our test data
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)

        helper = AstHelper("test.sol", "solidity", "")

        assert helper.input_type == "solidity"
        assert helper.allow_paths == ""
        assert "test.sol" in helper.source_list
        assert len(helper.contracts["contractsById"]) == 1

    def test_init_standard_json_input_type(self, mock_standard_json, mock_file_content):
        """Test AstHelper initialization with standard JSON input type."""
        with patch("builtins.open", mock_file_content(json.dumps(mock_standard_json))):
            helper = AstHelper("test.json", "standard json", "")

            assert helper.input_type == "standard json"
            assert "test.sol" in helper.source_list

    def test_init_invalid_input_type(self):
        """Test AstHelper initialization with invalid input type."""
        with pytest.raises(ValueError, match="Unsupported input type"):
            AstHelper("test.sol", "invalid", "")

    def test_get_source_list_standard_json(self, mock_standard_json, mock_file_content):
        """Test get_source_list_standard_json method."""
        with patch("builtins.open", mock_file_content(json.dumps(mock_standard_json))):
            helper = AstHelper("test.json", "standard json", "")

            result = helper.get_source_list_standard_json("dummy.json")

            assert result == mock_standard_json["sources"]

    def test_get_source_list_solidity_no_allow_paths(self, mock_solidity_ast):
        """Test get_source_list with Solidity input without allow_paths."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)

        helper = AstHelper("test.sol", "solidity", "")

        # Verify the command was called
        utils_mock.run_command.assert_called_once()
        assert "test.sol" in helper.source_list

    def test_get_source_list_solidity_with_allow_paths(self, mock_solidity_ast):
        """Test get_source_list with Solidity input with allow_paths."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        AstHelper("test.sol", "solidity", "", "/opt/libs")

        # Check that the command was called with allow_paths
        utils_mock.run_command.assert_called_once()
        call_args = utils_mock.run_command.call_args[0][0]  # Get the command string
        assert "/opt/libs" in call_args

    def test_get_source_list_with_v5_ast_conversion(self, mock_v5_ast):
        """Test get_source_list with v5+ AST that gets converted."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_v5_ast)
        helper = AstHelper("test.sol", "solidity", "")

        # Verify conversion was applied
        ast = helper.source_list["test.sol"]["AST"]
        assert ast["name"] == "SourceUnit"  # Converted format
        assert "children" in ast  # Should have children instead of nodes

    def test_extract_contract_definitions(self, mock_solidity_ast):
        """Test extract_contract_definitions method."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        contracts = helper.contracts

        assert "contractsById" in contracts
        assert "contractsByName" in contracts
        assert "sourcesByContract" in contracts
        assert "1" in contracts["contractsById"]
        assert "test.sol:TestContract" in contracts["contractsByName"]
        assert contracts["sourcesByContract"]["1"] == "test.sol"

    def test_get_linearized_base_contracts(self, mock_solidity_ast):
        """Test get_linearized_base_contracts method."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        contracts_by_id = helper.contracts["contractsById"]
        base_contracts = helper.get_linearized_base_contracts("1", contracts_by_id)

        assert len(base_contracts) == 1
        assert base_contracts[0]["id"] == "1"

    def test_extract_state_definitions(self, mock_solidity_ast):
        """Test extract_state_definitions method."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        state_vars = helper.extract_state_definitions("test.sol:TestContract")

        assert len(state_vars) == 1
        assert state_vars[0]["name"] == "VariableDeclaration"
        assert state_vars[0]["attributes"]["name"] == "owner"

    def test_extract_state_definitions_nonexistent_contract(self, mock_solidity_ast):
        """Test extract_state_definitions with nonexistent contract."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        state_vars = helper.extract_state_definitions("nonexistent:Contract")

        assert len(state_vars) == 0

    def test_extract_states_definitions(self, mock_solidity_ast):
        """Test extract_states_definitions method."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        all_states = helper.extract_states_definitions()

        assert "test.sol:TestContract" in all_states
        assert len(all_states["test.sol:TestContract"]) == 1

    def test_extract_func_call_definitions(self, mock_solidity_ast):
        """Test extract_func_call_definitions method."""
        # Add function call to mock AST
        import copy

        mock_ast = copy.deepcopy(mock_solidity_ast)
        func_call = {"name": "FunctionCall", "id": "4", "attributes": {"member_name": "transfer"}}

        # Ensure children array exists and add function call
        if "children" not in mock_ast["sources"]["test.sol"]["AST"]["children"][0]:
            mock_ast["sources"]["test.sol"]["AST"]["children"][0]["children"] = []
        mock_ast["sources"]["test.sol"]["AST"]["children"][0]["children"].append(func_call)

        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_ast)
        helper = AstHelper("test.sol", "solidity", "")

        func_calls = helper.extract_func_call_definitions("test.sol:TestContract")

        assert len(func_calls) == 1
        assert func_calls[0]["name"] == "FunctionCall"

    def test_extract_func_calls_definitions(self, mock_solidity_ast):
        """Test extract_func_calls_definitions method."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        all_func_calls = helper.extract_func_calls_definitions()

        assert "test.sol:TestContract" in all_func_calls
        assert isinstance(all_func_calls["test.sol:TestContract"], list)

    def test_extract_state_variable_names(self, mock_solidity_ast):
        """Test extract_state_variable_names method."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        var_names = helper.extract_state_variable_names("test.sol:TestContract")

        assert len(var_names) == 1
        assert "owner" in var_names

    def test_extract_func_call_srcs(self):
        """Test extract_func_call_srcs method."""
        mock_ast = {
            "sources": {
                "test.sol": {
                    "AST": {
                        "name": "SourceUnit",
                        "children": [
                            {
                                "name": "ContractDefinition",
                                "id": "1",
                                "attributes": {"name": "TestContract", "linearizedBaseContracts": ["1"]},
                                "children": [{"name": "FunctionCall", "src": "100:200:0"}],
                            }
                        ],
                    }
                }
            }
        }

        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_ast)
        helper = AstHelper("test.sol", "solidity", "")

        srcs = helper.extract_func_call_srcs("test.sol:TestContract")

        assert len(srcs) == 1
        assert "100:200:0" in srcs

    def test_get_callee_src_pairs(self):
        """Test get_callee_src_pairs method."""
        mock_ast = {
            "sources": {
                "test.sol": {
                    "AST": {
                        "name": "SourceUnit",
                        "children": [
                            {
                                "name": "ContractDefinition",
                                "id": "1",
                                "attributes": {"name": "TestContract", "linearizedBaseContracts": ["1"]},
                                "children": [
                                    {
                                        "name": "MemberAccess",
                                        "attributes": {"member_name": "call"},
                                        "src": "100:200:0",
                                        "children": [{"attributes": {"type": "contract OtherContract"}}],
                                    }
                                ],
                            },
                            {
                                "name": "ContractDefinition",
                                "id": "2",
                                "attributes": {"name": "OtherContract", "linearizedBaseContracts": ["2"]},
                            },
                        ],
                    }
                }
            }
        }

        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_ast)
        helper = AstHelper("test.sol", "solidity", "")

        pairs = helper.get_callee_src_pairs("test.sol:TestContract")

        assert len(pairs) == 1
        assert pairs[0] == ("test.sol:OtherContract", "100:200:0")

    def test_get_func_name_to_params(self):
        """Test get_func_name_to_params method."""
        mock_ast = {
            "sources": {
                "test.sol": {
                    "AST": {
                        "name": "SourceUnit",
                        "children": [
                            {
                                "name": "ContractDefinition",
                                "id": "1",
                                "attributes": {"name": "TestContract", "linearizedBaseContracts": ["1"]},
                                "children": [
                                    {
                                        "name": "FunctionDefinition",
                                        "attributes": {"name": "transfer"},
                                        "children": [
                                            {
                                                "name": "ParameterList",
                                                "children": [
                                                    {
                                                        "name": "VariableDeclaration",
                                                        "attributes": {"name": "to"},
                                                        "children": [{"name": "ElementaryTypeName"}],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                }
            }
        }

        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_ast)
        helper = AstHelper("test.sol", "solidity", "")

        params = helper.get_func_name_to_params("test.sol:TestContract")

        assert "transfer" in params
        assert len(params["transfer"]) == 1
        assert params["transfer"][0]["name"] == "to"
        assert params["transfer"][0]["type"] == "ElementaryTypeName"

    def test_get_func_name_to_params_with_array(self):
        """Test get_func_name_to_params with array parameter."""
        mock_ast = {
            "sources": {
                "test.sol": {
                    "AST": {
                        "name": "SourceUnit",
                        "children": [
                            {
                                "name": "ContractDefinition",
                                "id": "1",
                                "attributes": {"name": "TestContract", "linearizedBaseContracts": ["1"]},
                                "children": [
                                    {
                                        "name": "FunctionDefinition",
                                        "attributes": {"name": "batchTransfer"},
                                        "children": [
                                            {
                                                "name": "ParameterList",
                                                "children": [
                                                    {
                                                        "name": "VariableDeclaration",
                                                        "attributes": {"name": "amounts"},
                                                        "children": [
                                                            {
                                                                "name": "ArrayTypeName",
                                                                "children": [
                                                                    {"name": "Literal", "attributes": {"value": "10"}}
                                                                ],
                                                            }
                                                        ],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                }
            }
        }

        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_ast)
        helper = AstHelper("test.sol", "solidity", "")

        params = helper.get_func_name_to_params("test.sol:TestContract")

        assert "batchTransfer" in params
        assert params["batchTransfer"][0]["name"] == "amounts"
        assert params["batchTransfer"][0]["type"] == "ArrayTypeName"
        assert params["batchTransfer"][0]["value"] == 10

    def test_find_contract_path_found(self, mock_solidity_ast):
        """Test _find_contract_path when contract is found."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        paths = ["test.sol:TestContract", "other.sol:OtherContract"]
        result = helper._find_contract_path(paths, "TestContract")

        assert result == "test.sol:TestContract"

    def test_find_contract_path_not_found(self, mock_solidity_ast):
        """Test _find_contract_path when contract is not found."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_solidity_ast)
        helper = AstHelper("test.sol", "solidity", "")

        paths = ["test.sol:TestContract"]
        result = helper._find_contract_path(paths, "NonExistent")

        assert result == ""

    def test_semi_convert_new_to_old_ast_format(self, mock_v5_ast):
        """Test _semi_convert_new_to_old_ast_format method."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_v5_ast)
        helper = AstHelper("test.sol", "solidity", "")

        # Check that conversion was applied
        converted_ast = helper.source_list["test.sol"]["AST"]
        assert converted_ast["name"] == "SourceUnit"
        assert "children" in converted_ast


class TestAstHelperEdgeCases:
    """Test edge cases and error conditions for AstHelper."""

    def test_malformed_json_from_solc(self):
        """Test handling of malformed JSON from solc."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = "invalid json"

        with pytest.raises(json.JSONDecodeError):
            AstHelper("test.sol", "solidity", "")

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_missing_standard_json_file(self, mock_open_method):
        """Test handling of missing standard JSON file."""
        with pytest.raises(FileNotFoundError):
            AstHelper("test.json", "standard json", "")

    def test_empty_ast_sources(self):
        """Test handling of empty AST sources."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps({"sources": {}})

        helper = AstHelper("test.sol", "solidity", "")

        assert len(helper.source_list) == 0
        assert len(helper.contracts["contractsById"]) == 0

    def test_ast_without_contracts(self):
        """Test handling of AST without contract definitions."""
        mock_ast = {"sources": {"test.sol": {"AST": {"name": "SourceUnit", "children": []}}}}  # No contracts

        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_ast)

        helper = AstHelper("test.sol", "solidity", "")

        assert len(helper.contracts["contractsById"]) == 0
        assert len(helper.contracts["contractsByName"]) == 0

    def test_contract_without_children(self):
        """Test handling of contract without children."""
        mock_ast = {
            "sources": {
                "test.sol": {
                    "AST": {
                        "name": "SourceUnit",
                        "children": [
                            {
                                "name": "ContractDefinition",
                                "id": "1",
                                "attributes": {"name": "EmptyContract", "linearizedBaseContracts": ["1"]},
                                # No children
                            }
                        ],
                    }
                }
            }
        }

        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(mock_ast)

        helper = AstHelper("test.sol", "solidity", "")
        state_vars = helper.extract_state_definitions("test.sol:EmptyContract")

        assert len(state_vars) == 0

    def test_solc_command_failure(self):
        """Test handling of solc command failure."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.side_effect = Exception("Solc error")

        with pytest.raises(Exception, match="Solc error"):
            AstHelper("test.sol", "solidity", "")

        # Reset side_effect for subsequent tests
        utils_mock.run_command.side_effect = None


class TestAstHelperIntegration:
    """Integration tests for AstHelper with more realistic data."""

    @pytest.fixture
    def complex_ast(self) -> Dict[str, Any]:
        """Create a more complex, realistic AST structure."""
        return {
            "sources": {
                "Token.sol": {
                    "AST": {
                        "name": "SourceUnit",
                        "children": [
                            {
                                "name": "ContractDefinition",
                                "id": "1",
                                "attributes": {"name": "ERC20Token", "linearizedBaseContracts": ["1"]},
                                "children": [
                                    {"name": "VariableDeclaration", "id": "2", "attributes": {"name": "totalSupply"}},
                                    {"name": "VariableDeclaration", "id": "3", "attributes": {"name": "balances"}},
                                    {
                                        "name": "FunctionDefinition",
                                        "id": "4",
                                        "attributes": {"name": "transfer"},
                                        "children": [
                                            {
                                                "name": "Block",
                                                "children": [
                                                    {
                                                        "name": "FunctionCall",
                                                        "src": "100:200:0",
                                                        "attributes": {"member_name": "call"},
                                                    }
                                                ],
                                            }
                                        ],
                                    },
                                ],
                            }
                        ],
                    }
                }
            }
        }

    def test_complex_contract_analysis(self, complex_ast):
        """Test analysis of a more complex contract structure."""
        utils_mock.run_command.reset_mock()  # Reset mock between tests
        utils_mock.run_command.return_value = json.dumps(complex_ast)

        helper = AstHelper("Token.sol", "solidity", "")

        # Test contract extraction
        assert "Token.sol:ERC20Token" in helper.contracts["contractsByName"]

        # Test state variable extraction
        state_vars = helper.extract_state_variable_names("Token.sol:ERC20Token")
        assert "totalSupply" in state_vars
        assert "balances" in state_vars
        assert len(state_vars) == 2

        # Test function call extraction
        func_calls = helper.extract_func_call_definitions("Token.sol:ERC20Token")
        assert len(func_calls) == 1
        assert func_calls[0]["attributes"]["member_name"] == "call"

        # Test function call source extraction
        srcs = helper.extract_func_call_srcs("Token.sol:ERC20Token")
        assert "100:200:0" in srcs
