"""Unit tests for ast_walker module.

This module contains comprehensive unit tests for the AstWalker class,
testing AST traversal, node matching, and pattern-based searching
functionality.

Test Coverage:
    - Basic AST walking with single attributes
    - Pattern matching with multiple attribute sets
    - Recursive traversal of nested AST structures
    - Edge cases (empty trees, malformed nodes)
    - Attribute validation and matching logic
"""

import pytest
from unittest.mock import MagicMock
from typing import Any, Dict, List

from oyente.ast_walker import AstWalker


class TestAstWalker:
    """Test cases for AstWalker class."""

    def setup_method(self) -> None:
        """Set up test fixtures before each test method."""
        self.walker = AstWalker()

    def test_init(self) -> None:
        """Test AstWalker initialization."""
        walker = AstWalker()
        assert walker is not None

    def test_walk_with_single_attribute_match(self) -> None:
        """Test walking AST with single attribute that matches."""
        # Create mock AST node
        ast_node = {
            "name": "ContractDefinition",
            "id": "1",
            "attributes": {"name": "TestContract"}
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, {"name": "ContractDefinition"}, nodes)
        
        assert len(nodes) == 1
        assert nodes[0] == ast_node

    def test_walk_with_single_attribute_no_match(self) -> None:
        """Test walking AST with single attribute that doesn't match."""
        ast_node = {
            "name": "FunctionDefinition",
            "id": "1",
            "attributes": {"name": "testFunc"}
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, {"name": "ContractDefinition"}, nodes)
        
        assert len(nodes) == 0

    def test_walk_with_children_recursive(self) -> None:
        """Test recursive walking through AST children."""
        child_node = {
            "name": "FunctionDefinition",
            "id": "2",
            "attributes": {"name": "testFunc"}
        }
        
        parent_node = {
            "name": "ContractDefinition",
            "id": "1",
            "attributes": {"name": "TestContract"},
            "children": [child_node]
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(parent_node, {"name": "FunctionDefinition"}, nodes)
        
        assert len(nodes) == 1
        assert nodes[0] == child_node

    def test_walk_with_multiple_children(self) -> None:
        """Test walking AST with multiple children."""
        child1 = {
            "name": "FunctionDefinition",
            "id": "2",
            "attributes": {"name": "func1"}
        }
        
        child2 = {
            "name": "FunctionDefinition", 
            "id": "3",
            "attributes": {"name": "func2"}
        }
        
        parent_node = {
            "name": "ContractDefinition",
            "id": "1",
            "attributes": {"name": "TestContract"},
            "children": [child1, child2]
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(parent_node, {"name": "FunctionDefinition"}, nodes)
        
        assert len(nodes) == 2
        assert child1 in nodes
        assert child2 in nodes

    def test_walk_with_list_of_attributes_match(self) -> None:
        """Test walking with list of attributes where one matches."""
        ast_node = {
            "name": "FunctionCall",
            "attributes": {"member_name": "call"}
        }
        
        list_of_attributes = [
            {"attributes": {"member_name": "delegatecall"}},
            {"attributes": {"member_name": "call"}},
            {"attributes": {"member_name": "callcode"}}
        ]
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, list_of_attributes, nodes)
        
        assert len(nodes) == 1
        assert nodes[0] == ast_node

    def test_walk_with_list_of_attributes_no_match(self) -> None:
        """Test walking with list of attributes where none match."""
        ast_node = {
            "name": "FunctionCall",
            "attributes": {"member_name": "transfer"}
        }
        
        list_of_attributes = [
            {"attributes": {"member_name": "delegatecall"}},
            {"attributes": {"member_name": "call"}},
            {"attributes": {"member_name": "callcode"}}
        ]
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, list_of_attributes, nodes)
        
        assert len(nodes) == 0

    def test_walk_with_nested_attributes(self) -> None:
        """Test walking with nested attribute matching."""
        ast_node = {
            "name": "ContractDefinition",
            "attributes": {
                "name": "TestContract",
                "contractKind": "contract"
            }
        }
        
        attributes = {
            "name": "ContractDefinition",
            "attributes": {"contractKind": "contract"}
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, attributes, nodes)
        
        assert len(nodes) == 1
        assert nodes[0] == ast_node

    def test_walk_with_missing_nested_attributes(self) -> None:
        """Test walking fails when nested attributes are missing."""
        ast_node = {
            "name": "ContractDefinition",
            "attributes": {"name": "TestContract"}
        }
        
        attributes = {
            "name": "ContractDefinition", 
            "attributes": {"contractKind": "contract"}
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, attributes, nodes)
        
        assert len(nodes) == 0

    def test_walk_with_deep_nesting(self) -> None:
        """Test walking deeply nested AST structures."""
        target_node = {
            "name": "Literal",
            "attributes": {"value": "42"}
        }
        
        deep_nested = {
            "name": "ContractDefinition",
            "children": [{
                "name": "FunctionDefinition",
                "children": [{
                    "name": "Block",
                    "children": [target_node]
                }]
            }]
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(deep_nested, {"name": "Literal"}, nodes)
        
        assert len(nodes) == 1
        assert nodes[0] == target_node

    def test_walk_with_empty_children(self) -> None:
        """Test walking node with empty children list."""
        ast_node = {
            "name": "ContractDefinition",
            "children": []
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, {"name": "FunctionDefinition"}, nodes)
        
        assert len(nodes) == 0

    def test_walk_with_no_children_property(self) -> None:
        """Test walking node without children property."""
        ast_node = {
            "name": "Literal",
            "attributes": {"value": "test"}
        }
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_node, {"name": "FunctionDefinition"}, nodes)
        
        assert len(nodes) == 0

    def test_check_attributes_exact_match(self) -> None:
        """Test _check_attributes with exact attribute match."""
        node = {
            "name": "ContractDefinition",
            "id": "1"
        }
        
        attributes = {"name": "ContractDefinition"}
        
        result = self.walker._check_attributes(node, attributes)
        assert result is True

    def test_check_attributes_multiple_matches(self) -> None:
        """Test _check_attributes with multiple matching attributes."""
        node = {
            "name": "ContractDefinition",
            "id": "1",
            "src": "0:100:0"
        }
        
        attributes = {
            "name": "ContractDefinition",
            "id": "1"
        }
        
        result = self.walker._check_attributes(node, attributes)
        assert result is True

    def test_check_attributes_no_match(self) -> None:
        """Test _check_attributes with non-matching attributes."""
        node = {
            "name": "FunctionDefinition",
            "id": "1"
        }
        
        attributes = {"name": "ContractDefinition"}
        
        result = self.walker._check_attributes(node, attributes)
        assert result is False

    def test_check_attributes_missing_attribute(self) -> None:
        """Test _check_attributes when node is missing required attribute."""
        node = {"name": "ContractDefinition"}
        
        attributes = {
            "name": "ContractDefinition",
            "id": "1"
        }
        
        result = self.walker._check_attributes(node, attributes)
        assert result is False

    def test_check_attributes_value_mismatch(self) -> None:
        """Test _check_attributes when attribute values don't match."""
        node = {
            "name": "ContractDefinition",
            "id": "1"
        }
        
        attributes = {
            "name": "ContractDefinition",
            "id": "2"
        }
        
        result = self.walker._check_attributes(node, attributes)
        assert result is False

    def test_check_list_of_attributes_first_match(self) -> None:
        """Test _check_list_of_attributes when first pattern matches."""
        node = {
            "attributes": {"member_name": "delegatecall"}
        }
        
        list_of_attributes = [
            {"attributes": {"member_name": "delegatecall"}},
            {"attributes": {"member_name": "call"}}
        ]
        
        result = self.walker._check_list_of_attributes(node, list_of_attributes)
        assert result is True

    def test_check_list_of_attributes_second_match(self) -> None:
        """Test _check_list_of_attributes when second pattern matches."""
        node = {
            "attributes": {"member_name": "call"}
        }
        
        list_of_attributes = [
            {"attributes": {"member_name": "delegatecall"}},
            {"attributes": {"member_name": "call"}}
        ]
        
        result = self.walker._check_list_of_attributes(node, list_of_attributes)
        assert result is True

    def test_check_list_of_attributes_no_match(self) -> None:
        """Test _check_list_of_attributes when no pattern matches."""
        node = {
            "attributes": {"member_name": "transfer"}
        }
        
        list_of_attributes = [
            {"attributes": {"member_name": "delegatecall"}},
            {"attributes": {"member_name": "call"}}
        ]
        
        result = self.walker._check_list_of_attributes(node, list_of_attributes)
        assert result is False

    def test_check_list_of_attributes_empty_list(self) -> None:
        """Test _check_list_of_attributes with empty attribute list."""
        node = {"name": "ContractDefinition"}
        
        result = self.walker._check_list_of_attributes(node, [])
        assert result is False

    def test_walk_modifies_nodes_list_in_place(self) -> None:
        """Test that walk modifies the nodes list in place."""
        ast_node = {
            "name": "ContractDefinition",
            "id": "1"
        }
        
        nodes: List[Dict[str, Any]] = []
        original_id = id(nodes)
        
        self.walker.walk(ast_node, {"name": "ContractDefinition"}, nodes)
        
        # Verify same list object is modified
        assert id(nodes) == original_id
        assert len(nodes) == 1

    def test_walk_with_complex_real_world_structure(self) -> None:
        """Test walking with a more complex, realistic AST structure."""
        ast_tree = {
            "name": "SourceUnit",
            "children": [
                {
                    "name": "ContractDefinition",
                    "id": "1",
                    "attributes": {"name": "MyContract"},
                    "children": [
                        {
                            "name": "FunctionDefinition",
                            "id": "2",
                            "attributes": {"name": "constructor"},
                            "children": [
                                {
                                    "name": "Block",
                                    "children": [
                                        {
                                            "name": "ExpressionStatement",
                                            "children": [
                                                {
                                                    "name": "FunctionCall",
                                                    "attributes": {"member_name": "call"}
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "FunctionDefinition", 
                            "id": "3",
                            "attributes": {"name": "transfer"}
                        }
                    ]
                }
            ]
        }
        
        # Find all function definitions
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(ast_tree, {"name": "FunctionDefinition"}, nodes)
        
        assert len(nodes) == 2
        assert nodes[0]["id"] == "2"
        assert nodes[1]["id"] == "3"
        
        # Find specific function call patterns
        call_nodes: List[Dict[str, Any]] = []
        call_patterns = [
            {"attributes": {"member_name": "call"}},
            {"attributes": {"member_name": "delegatecall"}}
        ]
        self.walker.walk(ast_tree, call_patterns, call_nodes)
        
        assert len(call_nodes) == 1
        assert call_nodes[0]["attributes"]["member_name"] == "call"


class TestAstWalkerEdgeCases:
    """Test edge cases and error conditions for AstWalker."""

    def setup_method(self) -> None:
        """Set up test fixtures before each test method."""
        self.walker = AstWalker()

    def test_walk_with_none_node(self) -> None:
        """Test walking with None node returns no results."""
        nodes: List[Dict[str, Any]] = []
        
        # Should not raise an exception, just return empty results
        self.walker.walk(None, {"name": "Test"}, nodes)
        assert len(nodes) == 0

    def test_walk_with_malformed_node(self) -> None:
        """Test walking with malformed node structure."""
        malformed_node = "not_a_dict"
        nodes: List[Dict[str, Any]] = []
        
        with pytest.raises(AttributeError):
            self.walker.walk(malformed_node, {"name": "Test"}, nodes)

    def test_walk_with_circular_reference(self) -> None:
        """Test walking with circular reference in AST (infinite loop protection)."""
        # Create circular reference
        node1 = {"name": "Node1", "children": []}
        node2 = {"name": "Node2", "children": [node1]}
        node1["children"] = [node2]  # Create cycle
        
        nodes: List[Dict[str, Any]] = []
        
        # This should cause infinite recursion due to the cycle
        # Note: Current implementation doesn't have cycle detection,
        # so this test documents the limitation
        # In practice, ASTs shouldn't have cycles
        import sys
        original_limit = sys.getrecursionlimit()
        try:
            # Set a low recursion limit to trigger the error faster
            sys.setrecursionlimit(100)
            with pytest.raises(RecursionError):
                self.walker.walk(node1, {"name": "NonExistent"}, nodes)
        finally:
            sys.setrecursionlimit(original_limit)

    def test_check_attributes_with_none_attributes(self) -> None:
        """Test _check_attributes with None in attributes."""
        node = {"name": "Test", "value": None}
        attributes = {"name": "Test", "value": None}
        
        result = self.walker._check_attributes(node, attributes)
        assert result is True

    def test_check_attributes_with_empty_dict(self) -> None:
        """Test _check_attributes with empty attributes dict."""
        node = {"name": "Test", "id": "1"}
        attributes = {}
        
        result = self.walker._check_attributes(node, attributes)
        assert result is True

    def test_walk_performance_with_large_tree(self) -> None:
        """Test walking performance with a large AST tree."""
        # Create a large tree (breadth-first)
        root = {"name": "Root", "children": []}
        
        # Add 100 children to root
        for i in range(100):
            child = {
                "name": "Child",
                "id": str(i),
                "children": []
            }
            # Add 10 grandchildren to each child
            for j in range(10):
                grandchild = {
                    "name": "GrandChild" if j % 2 == 0 else "OtherNode",
                    "id": f"{i}_{j}"
                }
                child["children"].append(grandchild)
            root["children"].append(child)
        
        nodes: List[Dict[str, Any]] = []
        self.walker.walk(root, {"name": "GrandChild"}, nodes)
        
        # Should find 50 grandchildren (every other one)
        assert len(nodes) == 500  # 100 children * 5 grandchildren each