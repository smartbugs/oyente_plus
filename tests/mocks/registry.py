"""
Central mock registry for managing test mocks across the test suite.

This module provides a registry system for managing mock objects, ensuring
consistent mock behavior and preventing global state pollution.
"""

from __future__ import annotations

import sys
from typing import Any
from typing import Union
from unittest.mock import MagicMock
from unittest.mock import patch


class MockRegistry:
    """Central registry for managing mock objects in tests.

    Provides a single source of truth for all mocks, handles mock lifecycle,
    and ensures proper cleanup after tests.
    """

    def __init__(self):
        """Initialize the mock registry."""
        self._mocks: dict[str, Any] = {}
        self._patches: list[patch] = []
        self._original_modules: dict[str, Any] = {}

    def register_mock(self, module_name: str, mock_object: Any) -> None:
        """Register a mock object for a module.

        Args:
            module_name: Name of the module to mock
            mock_object: The mock object to use
        """
        self._mocks[module_name] = mock_object

    def get_mock(self, module_name: str) -> Union[Any, None]:
        """Get a registered mock object.

        Args:
            module_name: Name of the module

        Returns:
            The mock object if registered, None otherwise
        """
        return self._mocks.get(module_name)

    def patch_module(self, module_name: str, mock_object: Union[Any, None] = None) -> Any:
        """Patch a module with a mock object.

        Args:
            module_name: Name of the module to patch
            mock_object: Optional mock object (uses registered mock if not provided)

        Returns:
            The mock object being used
        """
        if mock_object is None:
            mock_object = self.get_mock(module_name)
            if mock_object is None:
                mock_object = MagicMock()
                self.register_mock(module_name, mock_object)

        # Store original module if it exists
        if module_name in sys.modules:
            self._original_modules[module_name] = sys.modules[module_name]

        # Patch the module
        sys.modules[module_name] = mock_object

        return mock_object

    def patch_attribute(self, target: str, attribute: str, mock_object: Any) -> None:
        """Patch an attribute of a module or class.

        Args:
            target: The target module/class path
            attribute: The attribute to patch
            mock_object: The mock object to use
        """
        patcher = patch(f"{target}.{attribute}", mock_object)
        self._patches.append(patcher)
        patcher.start()

    def reset_all(self) -> None:
        """Reset all mocks and restore original modules."""
        # Reset individual mocks
        for mock_obj in self._mocks.values():
            if hasattr(mock_obj, "reset_mock"):
                mock_obj.reset_mock()
            elif hasattr(mock_obj, "reset"):
                mock_obj.reset()

        # Stop all patches
        for patcher in self._patches:
            patcher.stop()
        self._patches.clear()

        # Restore original modules
        for module_name, original_module in self._original_modules.items():
            sys.modules[module_name] = original_module
        self._original_modules.clear()

        # Clear mock registry
        self._mocks.clear()

    def create_z3_mocks(self, mode: str = "unit") -> dict[str, Any]:
        """Create and register Z3-related mocks.

        Args:
            mode: Testing mode ('unit' or 'integration')

        Returns:
            Dictionary of created mocks
        """
        from tests.mocks.mock_z3 import MockZ3Factory

        # Create Z3 module mock
        z3_mock = MockZ3Factory.create_z3_module(mode=mode)
        self.register_mock("z3", z3_mock)

        # Create related mocks if needed for integration
        if mode == "integration":
            # Create global_params mock
            global_params_mock = MagicMock()
            global_params_mock.PARALLEL = False
            global_params_mock.TIMEOUT = 30000
            global_params_mock.UNIT_TEST = False
            global_params_mock.IS_TESTING_EVM = False
            global_params_mock.DEPTH_LIMIT = 50
            global_params_mock.LOOP_LIMIT = 10
            global_params_mock.GAS_LIMIT = 4000000
            global_params_mock.Ia = "0x1234567890123456789012345678901234567890"
            global_params_mock.Iv = 1000000000000000000
            global_params_mock.DISASM_CONTENT = None
            self.register_mock("global_params", global_params_mock)

            # Create other required mocks
            self.register_mock("analysis", MagicMock())
            self.register_mock("basicblock", MagicMock())
            self.register_mock("ethereum_data", MagicMock())
            self.register_mock("vargenerator", MagicMock())
            self.register_mock("vulnerability", MagicMock())
            self.register_mock("six", MagicMock())

        return self._mocks

    def create_crytic_compile_mocks(self) -> dict[str, Any]:
        """Create and register CryticCompile-related mocks.

        Returns:
            Dictionary of created mocks
        """
        import os

        from tests.mocks.mock_crytic_compile import MockCryticCompile
        from tests.mocks.mock_crytic_compile import MockInvalidCompilationError

        def mock_crytic_compile_constructor(source, *args, **kwargs):
            """Mock CryticCompile constructor that checks if source file exists."""
            # Check if the source file exists
            if not os.path.exists(source) and not source.startswith("http"):
                raise MockInvalidCompilationError(f"Source file not found: {source}")

            # If file exists, return successful mock
            return MockCryticCompile(source=source, **kwargs)

        # Use patch_attribute for classes within modules
        self.patch_attribute("input_helper", "CryticCompile", mock_crytic_compile_constructor)
        self.patch_attribute("input_helper", "InvalidCompilation", MockInvalidCompilationError)

        return {"CryticCompile": mock_crytic_compile_constructor, "InvalidCompilation": MockInvalidCompilationError}

    def setup_for_test(self, test_type: str = "unit") -> None:
        """Set up mocks for a specific test type.

        Args:
            test_type: Type of test ('unit', 'integration', 'performance', etc.)
        """
        if test_type in ["unit", "integration"]:
            self.create_z3_mocks(mode=test_type)

        # Set up CryticCompile mocks for integration tests
        if test_type == "integration":
            self.create_crytic_compile_mocks()

        # Apply all registered mocks to sys.modules
        for module_name, mock_obj in self._mocks.items():
            self.patch_module(module_name, mock_obj)

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup mocks."""
        self.reset_all()
        return False


# Global registry instance for convenience
_global_registry: Union[MockRegistry, None] = None


def get_global_registry() -> MockRegistry:
    """Get or create the global mock registry.

    Returns:
        The global MockRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = MockRegistry()
    return _global_registry


def reset_global_registry() -> None:
    """Reset the global mock registry."""
    global _global_registry
    if _global_registry is not None:
        _global_registry.reset_all()
        _global_registry = None
