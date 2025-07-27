"""AST Walker module for traversing and analyzing abstract syntax trees.

This module provides utilities for walking through AST nodes and finding nodes
that match specific attributes or criteria. It supports both single attribute
matching and multiple attribute pattern matching.

Typical usage:
    walker = AstWalker()
    nodes = []
    walker.walk(ast_root, {"name": "FunctionDefinition"}, nodes)
    # nodes now contains all function definition nodes
"""

from typing import Any
from typing import Dict
from typing import List
from typing import Union


class AstWalker:
    """AST walker for traversing syntax trees and collecting matching nodes.

    This class provides functionality to walk through AST nodes recursively
    and collect nodes that match specified attribute patterns. It supports
    both exact attribute matching and pattern-based matching with lists.

    Example:
        >>> walker = AstWalker()
        >>> nodes = []
        >>> walker.walk(ast_root, {"name": "ContractDefinition"}, nodes)
        >>> print(f"Found {len(nodes)} contract definitions")
    """

    def walk(
        self, node: Dict[str, Any], attributes: Union[Dict[str, Any], List[Dict[str, Any]]], nodes: List[Dict[str, Any]]
    ) -> None:
        """Walk the AST and collect nodes matching the given attributes.

        Args:
            node: The AST node to start walking from
            attributes: Either a dict of attributes to match exactly, or a list
                      of attribute dicts for pattern matching
            nodes: List to collect matching nodes (modified in-place)
        """
        if isinstance(attributes, dict):
            self._walk_with_attrs(node, attributes, nodes)
        else:
            self._walk_with_list_of_attrs(node, attributes, nodes)

    def _walk_with_attrs(self, node: Dict[str, Any], attributes: Dict[str, Any], nodes: List[Dict[str, Any]]) -> None:
        """Walk AST with exact attribute matching.

        Args:
            node: Current AST node to check
            attributes: Dictionary of attributes that must match exactly
            nodes: List to collect matching nodes (modified in-place)
        """
        if node is None:
            return

        if self._check_attributes(node, attributes):
            nodes.append(node)
        else:
            if node.get("children"):
                for child in node["children"]:
                    self._walk_with_attrs(child, attributes, nodes)

    def _walk_with_list_of_attrs(
        self, node: Dict[str, Any], list_of_attributes: List[Dict[str, Any]], nodes: List[Dict[str, Any]]
    ) -> None:
        """Walk AST with pattern matching using multiple attribute sets.

        Args:
            node: Current AST node to check
            list_of_attributes: List of attribute dicts to match against
            nodes: List to collect matching nodes (modified in-place)
        """
        if node is None:
            return

        if self._check_list_of_attributes(node, list_of_attributes):
            nodes.append(node)
        else:
            if node.get("children"):
                for child in node["children"]:
                    self._walk_with_list_of_attrs(child, list_of_attributes, nodes)

    def _check_attributes(self, node: Dict[str, Any], attributes: Dict[str, Any]) -> bool:
        """Check if a node matches the specified attributes exactly.

        Args:
            node: AST node to check
            attributes: Dictionary of attributes that must match

        Returns:
            True if all attributes match, False otherwise
        """
        if node is None:
            return False

        for name in attributes:
            if name == "attributes":
                if "attributes" not in node or not self._check_attributes(node["attributes"], attributes["attributes"]):
                    return False
            else:
                if name not in node or node[name] != attributes[name]:
                    return False
        return True

    def _check_list_of_attributes(self, node: Dict[str, Any], list_of_attributes: List[Dict[str, Any]]) -> bool:
        """Check if a node matches any of the attribute patterns.

        Args:
            node: AST node to check
            list_of_attributes: List of attribute patterns to match against

        Returns:
            True if node matches any pattern, False otherwise
        """
        return any(self._check_attributes(node, attrs) for attrs in list_of_attributes)
