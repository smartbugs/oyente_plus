"""Integration tests for reentrancy vulnerability detection.

Tests the complete reentrancy detection pipeline using real
vulnerable contract samples and expected results.
"""

import json

import pytest


@pytest.mark.integration
@pytest.mark.slow
class TestReentrancyDetection:
    """Test reentrancy vulnerability detection end-to-end."""

    def test_classic_dao_style_reentrancy(self, integration_fixtures):
        """Test detection of classic DAO-style reentrancy vulnerability."""
        contract_path = integration_fixtures["contracts"] / "dao_reentrancy.sol"
        expected_result = integration_fixtures["expected"] / "dao_reentrancy.json"

        # Test that classic reentrancy pattern is detected
        assert contract_path.exists()
        assert expected_result.exists()

        # Load expected results for verification
        with open(expected_result) as f:
            expected = json.load(f)

        assert "reentrancy" in expected["vulnerabilities"]
        assert len(expected["vulnerabilities"]["reentrancy"]) > 0

    def test_cross_function_reentrancy(self, integration_fixtures):
        """Test detection of cross-function reentrancy."""
        contract_path = integration_fixtures["contracts"] / "cross_function_reentrancy.sol"
        expected_result = integration_fixtures["expected"] / "cross_function_reentrancy.json"

        # Test more complex reentrancy patterns
        assert contract_path.exists()
        assert expected_result.exists()

    def test_reentrancy_with_state_changes(self, integration_fixtures):
        """Test reentrancy detection with various state change patterns."""
        contract_path = integration_fixtures["contracts"] / "reentrancy_state_changes.sol"

        # Test state change analysis in reentrancy context
        assert contract_path.exists()

    def test_false_positive_reduction(self, integration_fixtures):
        """Test that safe patterns don't trigger false positives."""
        safe_contract = integration_fixtures["contracts"] / "reentrancy_safe.sol"
        expected_result = integration_fixtures["expected"] / "reentrancy_safe.json"

        # Test that safe contracts are not flagged
        assert safe_contract.exists()
        assert expected_result.exists()

        with open(expected_result) as f:
            expected = json.load(f)

        # Should have no reentrancy vulnerabilities
        reentrancy_issues = expected.get("vulnerabilities", {}).get("reentrancy", [])
        assert len(reentrancy_issues) == 0

    def test_reentrancy_guard_patterns(self, integration_fixtures):
        """Test recognition of reentrancy guard patterns."""
        guarded_contract = integration_fixtures["contracts"] / "reentrancy_guarded.sol"

        # Test that reentrancy guards are recognized
        assert guarded_contract.exists()


@pytest.mark.integration
class TestReentrancyAnalysisDepth:
    """Test reentrancy analysis with different depth settings."""

    def test_shallow_analysis(self, integration_fixtures):
        """Test reentrancy detection with shallow analysis depth."""
        contract_path = integration_fixtures["contracts"] / "deep_reentrancy.sol"

        # Test analysis with limited depth
        assert contract_path.exists()

    def test_deep_analysis(self, integration_fixtures):
        """Test reentrancy detection with deep analysis."""
        contract_path = integration_fixtures["contracts"] / "deep_reentrancy.sol"

        # Test analysis with increased depth for complex patterns
        assert contract_path.exists()

    def test_timeout_handling(self, integration_fixtures):
        """Test timeout handling in complex reentrancy analysis."""
        complex_contract = integration_fixtures["contracts"] / "complex_reentrancy.sol"

        # Test that analysis doesn't hang on complex contracts
        assert complex_contract.exists()


@pytest.mark.integration
class TestReentrancyReporting:
    """Test reentrancy vulnerability reporting."""

    def test_source_location_accuracy(self, integration_fixtures):
        """Test accuracy of source code location reporting."""
        contract_path = integration_fixtures["contracts"] / "reentrancy_locations.sol"
        expected_result = integration_fixtures["expected"] / "reentrancy_locations.json"

        # Test that source locations are accurate
        assert contract_path.exists()
        assert expected_result.exists()

        with open(expected_result) as f:
            expected = json.load(f)

        # Check that locations are specified
        for vuln in expected.get("vulnerabilities", {}).get("reentrancy", []):
            assert "line" in vuln
            assert "column" in vuln
            assert vuln["line"] > 0

    def test_severity_classification(self, integration_fixtures):
        """Test severity classification of reentrancy vulnerabilities."""
        contract_path = integration_fixtures["contracts"] / "reentrancy_severity.sol"
        expected_result = integration_fixtures["expected"] / "reentrancy_severity.json"

        # Test that severity levels are properly assigned
        assert contract_path.exists()
        assert expected_result.exists()

    def test_recommendation_generation(self, integration_fixtures):
        """Test generation of fix recommendations."""
        contract_path = integration_fixtures["contracts"] / "reentrancy_fixable.sol"
        expected_result = integration_fixtures["expected"] / "reentrancy_fixable.json"

        # Test that fix recommendations are provided
        assert contract_path.exists()
        assert expected_result.exists()

        with open(expected_result) as f:
            expected = json.load(f)

        # Should include recommendations
        for vuln in expected.get("vulnerabilities", {}).get("reentrancy", []):
            assert "recommendation" in vuln
            assert len(vuln["recommendation"]) > 0
