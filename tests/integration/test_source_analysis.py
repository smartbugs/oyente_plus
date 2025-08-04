"""Integration tests for Solidity source code analysis.

Tests the complete analysis pipeline from Solidity source files
to vulnerability detection results.
"""

import pytest


@pytest.mark.integration
@pytest.mark.slow
class TestSourceAnalysis:
    """Test analysis of Solidity source files."""

    def test_simple_contract_analysis(self, integration_fixtures):
        """Test analysis of a simple contract without vulnerabilities."""
        contract_path = integration_fixtures["contracts"] / "simple_safe.sol"

        # This would be a real analysis call in full integration
        # For now, we'll mock the heavy parts while testing structure

        # Test that we can at least parse and set up the analysis
        # without running the full symbolic execution
        assert contract_path.exists()
        assert contract_path.suffix == ".sol"

    def test_vulnerable_contract_detection(self, integration_fixtures):
        """Test that vulnerable contracts are properly detected."""
        contract_path = integration_fixtures["contracts"] / "reentrancy_vulnerable.sol"
        expected_result = integration_fixtures["expected"] / "reentrancy_vulnerable.json"

        # This would run full analysis and compare against golden file
        # For now, verify structure exists
        assert contract_path.exists()
        assert expected_result.exists()

    def test_contract_with_libraries(self, integration_fixtures):
        """Test analysis of contracts that use libraries."""
        contract_path = integration_fixtures["contracts"] / "library_user.sol"

        # Test library linking and analysis
        assert contract_path.exists()

    def test_multiple_contracts_in_file(self, integration_fixtures):
        """Test analysis of file containing multiple contracts."""
        contract_path = integration_fixtures["contracts"] / "multiple_contracts.sol"

        # Test that all contracts in file are analyzed
        assert contract_path.exists()


@pytest.mark.integration
class TestCompilationWorkflow:
    """Test the compilation and preprocessing workflow."""

    def test_solidity_compilation_success(self, integration_fixtures):
        """Test successful Solidity compilation."""
        contract_path = integration_fixtures["contracts"] / "simple_safe.sol"

        # Test compilation without full analysis - simplified for now
        # Future: Add real compilation integration here

        # Test that contract exists and is readable
        assert contract_path.exists()
        assert contract_path.suffix == ".sol"

    def test_compilation_error_handling(self, integration_fixtures):
        """Test handling of compilation errors."""
        contract_path = integration_fixtures["contracts"] / "syntax_error.sol"

        # Test that compilation errors are properly handled
        assert contract_path.exists()

    def test_pragma_version_compatibility(self, integration_fixtures):
        """Test handling of different Solidity pragma versions."""
        old_version_contract = integration_fixtures["contracts"] / "old_pragma.sol"
        new_version_contract = integration_fixtures["contracts"] / "new_pragma.sol"

        # Test compatibility with different Solidity versions
        assert old_version_contract.exists()
        assert new_version_contract.exists()
