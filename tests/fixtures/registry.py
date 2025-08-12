"""
Fixture registry for centralized test fixture management.

This module provides a registry system for managing test fixtures,
allowing for easy discovery, loading, and organization of test data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .data_generators import AnalysisResultFactory
from .data_generators import BytecodeFactory
from .data_generators import SolidityContractFactory
from .data_generators import SymbolicExecutionFactory
from .data_generators import TestScenarioFactory
from .data_generators import VulnerabilityPatternFactory


class FixtureRegistry:
    """
    Central registry for managing all test fixtures.

    This class provides a unified interface for accessing contracts,
    bytecode, expected results, and generated test data.
    """

    def __init__(self, fixtures_root: Path | None = None) -> None:
        """
        Initialize the fixture registry.

        Args:
            fixtures_root: Root directory for fixtures. If None, uses tests/fixtures.
        """
        if fixtures_root is None:
            fixtures_root = Path(__file__).parent

        self.fixtures_root = fixtures_root
        self.contracts_dir = fixtures_root / "contracts"
        self.bytecode_dir = fixtures_root / "bytecode"
        self.expected_dir = fixtures_root / "expected_results"

        # Cache for loaded fixtures
        self._cache: dict[str, Any] = {}

        # Factory instances
        self.contract_factory = SolidityContractFactory()
        self.bytecode_factory = BytecodeFactory()
        self.analysis_factory = AnalysisResultFactory
        self.scenario_factory = TestScenarioFactory()
        self.symexec_factory = SymbolicExecutionFactory()
        self.vuln_factory = VulnerabilityPatternFactory()

    def get_contract(self, name: str, category: str = "safe") -> str:
        """
        Get contract source code by name and category.

        Args:
            name: Contract name (without .sol extension)
            category: Contract category (safe, vulnerable, edge_cases)

        Returns:
            Contract source code

        Raises:
            FileNotFoundError: If contract file not found
        """
        cache_key = f"contract_{category}_{name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        contract_file = self.contracts_dir / category / f"{name}.sol"
        if not contract_file.exists():
            # Try without category subdirectory
            contract_file = self.contracts_dir / f"{name}.sol"

        if not contract_file.exists():
            raise FileNotFoundError(f"Contract not found: {name} in category {category}")

        source_code = contract_file.read_text(encoding="utf-8")
        self._cache[cache_key] = source_code
        return source_code

    def get_bytecode(self, name: str) -> str:
        """
        Get bytecode by name.

        Args:
            name: Bytecode file name (without .bin extension)

        Returns:
            Bytecode string

        Raises:
            FileNotFoundError: If bytecode file not found
        """
        cache_key = f"bytecode_{name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        bytecode_file = self.bytecode_dir / f"{name}.bin"
        if not bytecode_file.exists():
            raise FileNotFoundError(f"Bytecode not found: {name}")

        bytecode = bytecode_file.read_text(encoding="utf-8").strip()
        self._cache[cache_key] = bytecode
        return bytecode

    def get_expected_result(self, name: str) -> dict[str, Any]:
        """
        Get expected analysis result by name.

        Args:
            name: Expected result file name (without .json extension)

        Returns:
            Expected analysis result as dictionary

        Raises:
            FileNotFoundError: If expected result file not found
        """
        cache_key = f"expected_{name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        expected_file = self.expected_dir / f"{name}.json"
        if not expected_file.exists():
            raise FileNotFoundError(f"Expected result not found: {name}")

        with expected_file.open(encoding="utf-8") as f:
            result = json.load(f)

        self._cache[cache_key] = result
        return result

    def list_contracts(self, category: str | None = None) -> list[str]:
        """
        List available contracts.

        Args:
            category: Optional category filter (safe, vulnerable, edge_cases)

        Returns:
            List of contract names (without .sol extension)
        """
        contracts = []

        if category:
            category_dir = self.contracts_dir / category
            if category_dir.exists():
                contracts.extend([f.stem for f in category_dir.glob("*.sol")])
        else:
            # List all contracts from all categories
            for category_dir in self.contracts_dir.iterdir():
                if category_dir.is_dir():
                    contracts.extend([f.stem for f in category_dir.glob("*.sol")])

            # Also include contracts directly in contracts directory
            contracts.extend([f.stem for f in self.contracts_dir.glob("*.sol")])

        return sorted(set(contracts))

    def list_bytecode(self) -> list[str]:
        """
        List available bytecode files.

        Returns:
            List of bytecode names (without .bin extension)
        """
        if not self.bytecode_dir.exists():
            return []

        return sorted([f.stem for f in self.bytecode_dir.glob("*.bin")])

    def list_expected_results(self) -> list[str]:
        """
        List available expected result files.

        Returns:
            List of expected result names (without .json extension)
        """
        if not self.expected_dir.exists():
            return []

        return sorted([f.stem for f in self.expected_dir.glob("*.json")])

    def generate_contract(self, pattern: str, **kwargs: Any) -> str:
        """
        Generate contract using factories.

        Args:
            pattern: Contract pattern name
            **kwargs: Additional parameters for generation

        Returns:
            Generated contract source code
        """
        generators = {
            "simple_storage": self.contract_factory.simple_storage,
            "token_contract": self.contract_factory.token_contract,
            "vulnerable_reentrancy": self.contract_factory.vulnerable_reentrancy,
            "integer_overflow": self.contract_factory.integer_overflow,
            "timestamp_dependency": self.contract_factory.timestamp_dependency,
            "delegatecall_vulnerability": self.contract_factory.delegatecall_vulnerability,
            "complex_defi": self.contract_factory.complex_defi,
        }

        generator = generators.get(pattern)
        if not generator:
            available = ", ".join(generators.keys())
            raise ValueError(f"Unknown pattern: {pattern}. Available: {available}")

        return generator()

    def generate_bytecode(self, pattern: str, **kwargs: Any) -> str:
        """
        Generate bytecode using factories.

        Args:
            pattern: Bytecode pattern name
            **kwargs: Additional parameters for generation

        Returns:
            Generated bytecode string
        """
        generators = {
            "simple": self.bytecode_factory.simple_bytecode,
            "with_jumps": self.bytecode_factory.with_jumps,
            "with_storage": self.bytecode_factory.with_storage,
            "with_external_calls": self.bytecode_factory.with_external_calls,
            "random": lambda: self.bytecode_factory.random_bytecode(**kwargs),
            "from_opcodes": lambda: self.bytecode_factory.from_opcodes(kwargs.get("opcodes", [])),
        }

        generator = generators.get(pattern)
        if not generator:
            available = ", ".join(generators.keys())
            raise ValueError(f"Unknown pattern: {pattern}. Available: {available}")

        return generator()

    def generate_analysis_result(self, vulnerabilities: list[str] | None = None) -> dict[str, Any]:
        """
        Generate analysis result using factory.

        Args:
            vulnerabilities: List of vulnerabilities to include

        Returns:
            Generated analysis result
        """
        if vulnerabilities:
            return self.analysis_factory.with_vulnerabilities(vulnerabilities)
        else:
            return self.analysis_factory()

    def generate_test_scenario(
        self, scenario_type: str = "simple", vulnerability_type: str | None = None
    ) -> dict[str, Any]:
        """
        Generate test scenario using factory.

        Args:
            scenario_type: Type of scenario (simple, vulnerable)
            vulnerability_type: Specific vulnerability type for vulnerable scenarios

        Returns:
            Generated test scenario
        """
        if scenario_type == "simple":
            return self.scenario_factory.simple_analysis_scenario()
        elif scenario_type == "vulnerable" and vulnerability_type:
            return self.scenario_factory.vulnerable_scenario(vulnerability_type)
        else:
            raise ValueError(f"Unknown scenario type: {scenario_type}")

    def generate_symexec_state(self, complexity: str = "basic") -> dict[str, Any]:
        """
        Generate symbolic execution state using factory.

        Args:
            complexity: Complexity level (basic, complex)

        Returns:
            Generated symbolic execution state
        """
        if complexity == "basic":
            return self.symexec_factory.basic_parameter_state()
        elif complexity == "complex":
            return self.symexec_factory.complex_parameter_state()
        else:
            raise ValueError(f"Unknown complexity: {complexity}")

    def generate_vulnerability_pattern(self, vuln_type: str) -> dict[str, Any]:
        """
        Generate vulnerability pattern using factory.

        Args:
            vuln_type: Vulnerability type (reentrancy, integer_overflow, timestamp_dependency)

        Returns:
            Generated vulnerability pattern
        """
        generators = {
            "reentrancy": self.vuln_factory.reentrancy_pattern,
            "integer_overflow": self.vuln_factory.integer_overflow_pattern,
            "timestamp_dependency": self.vuln_factory.timestamp_dependency_pattern,
        }

        generator = generators.get(vuln_type)
        if not generator:
            available = ", ".join(generators.keys())
            raise ValueError(f"Unknown vulnerability type: {vuln_type}. Available: {available}")

        return generator()

    def clear_cache(self) -> None:
        """Clear the fixture cache."""
        self._cache.clear()

    def get_cache_stats(self) -> dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "cached_items": len(self._cache),
            "available_contracts": len(self.list_contracts()),
            "available_bytecode": len(self.list_bytecode()),
            "available_expected": len(self.list_expected_results()),
        }


# Global fixture registry instance
fixture_registry = FixtureRegistry()
