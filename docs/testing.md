# Testing Guide

This document explains the testing structure and workflows for Oyente+, covering unit tests, integration tests, and other testing types.

## Current Status

- **Total Tests**: 494 test functions (429 unit + 65 integration) executed with 100% pass rate
- **Pass Rate**: 100% (no skipped tests currently)
- **Test Files**: Comprehensive test files covering core modules
- **Test Categories**: Unit, Integration, Property, Performance
- **Coverage**: All core modules have test coverage
- **Infrastructure**: Modernized with centralized fixture registry and factories

## Test Organization

Following industry best practices, our tests are organized into distinct categories:

```text
tests/
├── unit/           # Fast, isolated tests
├── integration/    # Component interaction tests
├── property/       # Hypothesis property-based tests
├── performance/    # Benchmark tests (pytest-benchmark)
├── fixtures/       # Centralized fixture library
│   ├── contracts/  # Static Solidity contracts by category (safe/vulnerable/edge_cases)
│   ├── bytecode/   # EVM bytecode samples
│   ├── expected_results/  # Golden files for integration tests
│   ├── factories/  # Test data factories (contract, analysis, vulnerability)
│   ├── data_generators.py  # Comprehensive data generators
│   └── registry.py # Central fixture registry with caching
├── mocks/          # Mock objects (Z3, filesystem, subprocess, crytic-compile)
│   └── registry.py # Central mock registry
└── templates/      # Test templates for common patterns
```

## Test Types

### Unit Tests (`tests/unit/`)

**Purpose**: Test individual functions and classes in isolation
**Test Count**: 429 unit test functions
**Execution Time**: < 10 seconds total
**Dependencies**: No external tools, filesystem, or network

**Characteristics**:

- Use mocks for all external dependencies
- Test single functions or classes
- Fast execution for immediate feedback
- Run on every code change

**Examples**:

- `test_vulnerability.py`: 40+ tests for all vulnerability detectors
- `test_analysis.py`: 40+ tests for analysis functions
- `test_input_helper.py`: 45+ tests including property-based testing
- `test_symexec.py`: 25+ tests for symbolic execution components
- `test_basicblock.py`: 50+ tests for basic block operations
- `test_utils.py`: 50+ tests for utility functions
- `test_vargenerator.py`: 40+ tests for variable generation
- `test_ast_helper.py`: 30+ tests with complex mocking
- `test_ast_walker.py`: 30+ tests for AST traversal

### Integration Tests (`tests/integration/`)

**Purpose**: Test component interactions and workflows
**Test Count**: 65 integration test functions
**Execution Time**: < 3 minutes total
**Dependencies**: May use external tools (solc, Z3) and real file I/O

**Characteristics**:

- Test multiple components working together
- May involve real compilation and analysis
- Use real Solidity contracts as test data
- Test CLI workflows and end-to-end scenarios

**Examples**:

- Full Solidity compilation pipeline
- Bytecode analysis workflows
- CLI argument parsing and execution
- Vulnerability detection on real contracts

### Property Tests (`tests/property/`)

**Purpose**: Test invariants and properties using generated inputs
**Tool**: Hypothesis framework
**Focus**: Edge cases and property validation

### Performance Tests (`tests/performance/`)

**Purpose**: Benchmark performance and detect regressions
**Tool**: pytest-benchmark
**Focus**: Execution time and memory usage

## Running Tests

### Quick Commands (Recommended)

```bash
# Development workflow - run before each commit
make test          # Unit tests only (429 tests, ~8 seconds)
make all          # Full quality checks including unit tests

# Specific test types
make test-unit           # Unit tests only
make test-integration    # Integration tests only
make test-performance    # Performance benchmarks
make test-property       # Property-based tests

# With coverage
make test-cov            # Unit tests with coverage
make test-integration-cov # Integration tests with coverage
```

### Direct pytest Commands

```bash
# Unit tests (default - excludes integration)
pytest                               # All unit tests
pytest tests/unit/                   # Explicit unit test directory
pytest -m unit                       # By marker

# Integration tests
pytest -m integration                # Integration tests only
pytest tests/integration/            # Integration test directory
pytest --integration                 # If custom option added

# Run all tests (including integration)
pytest tests/ -m "unit or integration"
pytest --runintegration             # If custom option added

# Specific test files
pytest tests/unit/test_vulnerability.py
pytest tests/integration/test_reentrancy_detector.py

# Coverage reporting
pytest --cov=oyente tests/unit/      # Unit test coverage
pytest --cov=oyente tests/integration/ # Integration test coverage
pytest --cov=oyente tests/ -m "unit or integration" # Combined coverage
```

### Running Single Tests via Makefile

The Makefile provides convenient targets for running individual tests:

```bash
# Run a single test file
make test TEST=tests/unit/test_vulnerability.py

# Run a specific test class
make test TEST=tests/unit/test_vulnerability.py::TestReentrancy

# Run a specific test method
make test TEST=tests/unit/test_vulnerability.py::TestReentrancy::test_basic_detection

# Run single test with coverage
make test-cov TEST=tests/unit/test_vulnerability.py

# Examples for different test types
make test TEST=tests/unit/test_symexec.py              # Unit test file
make test TEST=tests/integration/test_compilation_workflow.py  # Integration test file
make test TEST=tests/performance/test_benchmarks.py    # Performance test file
```

### Test Markers

Our tests use pytest markers for organization:

```bash
# By test type
pytest -m unit           # Unit tests
pytest -m integration    # Integration tests
pytest -m property       # Property-based tests
pytest -m performance    # Performance tests

# By criticality and purpose (NEW)
pytest -m smoke          # Smoke tests (critical path)
pytest -m regression     # Regression tests
pytest -m fuzzing        # Fuzz tests
pytest -m mutation       # Mutation tests

# By speed
pytest -m "not slow"     # Skip slow tests
pytest -m slow           # Only slow tests

# By dependencies
pytest -m requires_z3    # Tests requiring Z3 solver
pytest -m requires_solc  # Tests requiring Solidity compiler

# Combinations
pytest -m "unit and not slow"              # Fast unit tests only
pytest -m "integration and requires_solc"  # Integration tests with Solidity
pytest -m "smoke or regression"            # Critical and regression tests
pytest -m "fuzzing and property"           # Property-based fuzz tests
```

## Test Configuration

### Default Behavior

- **make test** / **pytest** (no arguments): Runs unit tests only (excludes integration)
- Integration tests are excluded by default for fast development cycles
- Use explicit commands or markers to run integration tests

### Configuration in pyproject.toml

```toml
[tool.pytest.ini_options]
addopts = [
    "-m 'not integration'",  # Exclude integration tests by default
]
markers = [
    "unit: marks tests as unit tests",
    "integration: marks tests as integration tests",
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "property: marks tests as property-based tests",
    "performance: marks tests as performance tests",
    "requires_z3: marks tests that require Z3 solver",
    "requires_solc: marks tests that require Solidity compiler",
    "smoke: marks tests as smoke tests (critical path)",
    "regression: marks tests as regression tests",
    "fuzzing: marks tests as fuzz tests",
    "mutation: marks tests as mutation tests",
]
```

## Writing Tests

### Unit Test Guidelines

**DO**:

- Test single functions or classes
- Use mocks for all external dependencies
- Focus on algorithmic correctness
- Keep execution time under milliseconds
- Test edge cases and error conditions

**DON'T**:

- Access filesystem or network
- Call external processes
- Test multiple components together
- Use real Solidity compilation

**Example**:

```python
def test_vulnerability_detection_logic():
    \"\"\"Test vulnerability detection algorithm (unit test).\"\"\"
    # Mock all dependencies
    mock_solver = Mock()
    mock_solver.check.return_value = "sat"

    detector = ReentrancyDetector(mock_source_map, [])
    result = detector._analyze_pattern(mock_bytecode)

    assert result.is_vulnerable
    mock_solver.check.assert_called_once()
```

### Integration Test Guidelines

**DO**:

- Test component interactions
- Use real files and external tools when needed
- Test complete workflows
- Verify end-to-end behavior
- Use integration fixtures

**DON'T**:

- Test internal implementation details
- Duplicate unit test logic
- Create overly complex scenarios
- Ignore timeout and performance

**Example**:

```python
@pytest.mark.integration
def test_solidity_compilation_workflow(integration_fixtures):
    \"\"\"Test full Solidity compilation workflow (integration test).\"\"\"
    contract_path = integration_fixtures["contracts"] / "simple_safe.sol"

    # Test real compilation
    helper = InputHelper(InputHelper.SOLIDITY, source=str(contract_path))
    contracts = helper.get_contracts()

    assert len(contracts) > 0
    assert contracts[0][0].endswith("SimpleSafe")
```

## Test Templates

To standardize test creation and ensure consistent patterns, we provide comprehensive test templates in `tests/templates/`:

### Available Templates

1. **`vulnerability_test_template.py`** - Template for vulnerability detection tests
2. **`integration_test_template.py`** - Template for integration and end-to-end tests
3. **`mutation_test_template.py`** - Template for mutation testing (test quality validation)

### Using Templates

**Step 1**: Copy the appropriate template to your test file location

```bash
cp tests/templates/vulnerability_test_template.py tests/unit/test_my_detector.py
```

**Step 2**: Replace placeholders in the copied file

- `CLASS_NAME` → Your component name (e.g., "ReentrancyDetector")
- `MODULE_NAME` → Module path (e.g., "symExec")
- `FUNCTION_NAME` → Function to test (e.g., "detect_reentrancy")

**Step 3**: Implement specific test cases using the template structure

### Template Features

Each template includes:

- **Proper markers**: `@pytest.mark.smoke`, `@pytest.mark.regression`, etc.
- **Factory usage**: Integration with test data factories
- **Error handling**: Comprehensive error scenario testing
- **Performance tests**: Basic performance validation
- **Property-based tests**: Integration with hypothesis for fuzzing
- **Documentation**: Inline examples and usage patterns

### Example Template Usage

```python
# From vulnerability_test_template.py
class TestReentrancyDetectorVulnerabilityDetection:
    """Test vulnerability detection for ReentrancyDetector."""

    @pytest.mark.smoke
    def test_detects_reentrancy_vulnerability(self, fixtures, mock_z3_solver):
        # Arrange
        vulnerable_contract = self.contract_factory.vulnerable_reentrancy()

        # Act
        result = detect_reentrancy(vulnerable_contract["source_code"])

        # Assert
        assert len(result["reentrancy_bug"]) > 0
```

## Test Fixtures and Data

Our testing infrastructure features a centralized fixture library that provides both static test data and dynamic test data generation through factories.

### Centralized Fixture Registry (`tests/fixtures/registry.py`)

The `FixtureRegistry` class provides a unified interface for accessing all test fixtures:

```python
from tests.fixtures.registry import fixture_registry

# Access static contract files
contract_source = fixture_registry.get_contract("reentrancy_vulnerable", category="vulnerable")

# Access bytecode samples
bytecode = fixture_registry.get_bytecode("simple_contract")

# Access expected results
expected = fixture_registry.get_expected_result("reentrancy_vulnerable")

# Generate dynamic test data
contract_data = fixture_registry.generate_contract("vulnerable_reentrancy")
analysis_result = fixture_registry.generate_analysis_result(["reentrancy"])
```

### Static Contract Library (`tests/fixtures/contracts/`)

Organized by vulnerability categories:

```text
tests/fixtures/contracts/
├── safe/                    # Safe, well-written contracts
│   ├── basic_token.sol      # Simple ERC20-like token
│   ├── simple_safe.sol      # Basic safe contract
│   ├── simple_storage.sol   # Storage contract
│   └── reentrancy_safe.sol  # Reentrancy-protected contract
├── vulnerable/              # Known vulnerable contracts
│   ├── reentrancy_vulnerable.sol     # Classic reentrancy vulnerability
│   ├── cross_function_reentrancy.sol # Complex reentrancy patterns
│   ├── integer_overflow.sol          # Integer overflow (pre-0.8.0)
│   ├── timestamp_dependency.sol      # Timestamp manipulation
│   └── dao_reentrancy.sol           # DAO-style reentrancy
└── edge_cases/              # Edge cases and error conditions
    ├── syntax_error.sol     # Invalid Solidity syntax
    ├── old_pragma.sol       # Old Solidity versions
    ├── multiple_contracts.sol # Multiple contracts in one file
    └── library_user.sol     # Contract using libraries
```

### Test Data Factories (`tests/fixtures/factories/`)

Factory classes for generating realistic test data:

#### Contract Factory (`tests/fixtures/factories/contract.py`)

```python
from tests.fixtures.factories.contract import ContractFactory

# Generate specific contract types
safe_contract = ContractFactory.simple_storage()
token_contract = ContractFactory.erc20_token()
vulnerable_contract = ContractFactory.vulnerable_reentrancy()
```

#### Analysis Factory (`tests/fixtures/factories/analysis.py`)

```python
from tests.fixtures.factories.analysis import AnalysisFactory

# Generate analysis results
safe_result = AnalysisFactory.safe_contract()
reentrancy_result = AnalysisFactory.with_reentrancy([100, 150, 200])
multi_vuln_result = AnalysisFactory.with_multiple_vulnerabilities(["reentrancy", "overflow"])
```

#### Vulnerability Factory (`tests/fixtures/factories/vulnerability.py`)

```python
from tests.fixtures.factories.vulnerability import VulnerabilityFactory

# Generate specific vulnerability patterns
reentrancy_vuln = VulnerabilityFactory.reentrancy()
overflow_vuln = VulnerabilityFactory.integer_overflow()
security_report = SecurityReportFactory.vulnerable_contract_report(["reentrancy"])
```

### Integration Test Data

**Expected Results** (`tests/fixtures/expected_results/`):

- `*.json` files containing expected analysis outcomes
- Used for regression testing and validation
- Covers different vulnerability types and contract patterns

**Bytecode Samples** (`tests/fixtures/bytecode/`):

- `*.bin` files with EVM bytecode for various patterns
- Includes edge cases like malformed bytecode
- Used for bytecode analysis testing

### Using Fixtures in Tests

#### Static Fixtures

```python
def test_contract_analysis(fixture_registry):
    contract_source = fixture_registry.get_contract("reentrancy_vulnerable", "vulnerable")
    expected = fixture_registry.get_expected_result("reentrancy_vulnerable")

    # Perform analysis
    result = analyze_contract(contract_source)
    assert result["reentrancy_bug"] == expected["reentrancy_bug"]
```

#### Dynamic Fixtures

```python
def test_vulnerability_detection():
    # Generate realistic test data
    contract = fixture_registry.generate_contract("vulnerable_reentrancy")
    expected_analysis = fixture_registry.generate_analysis_result(["reentrancy"])

    # Test with generated data
    result = analyze_contract(contract["source_code"])
    assert len(result["reentrancy_bug"]) > 0
```

#### Fixture Discovery

```python
# List available fixtures
contracts = fixture_registry.list_contracts()                    # All contracts
safe_contracts = fixture_registry.list_contracts("safe")         # Safe contracts only
bytecode_files = fixture_registry.list_bytecode()               # Available bytecode
expected_results = fixture_registry.list_expected_results()     # Expected results

# Cache statistics
stats = fixture_registry.get_cache_stats()
print(f"Cached items: {stats['cached_items']}")
```

## CI/CD Integration

### Local Development

```bash
# Before committing (fast feedback)
make test          # Unit tests only (~1-5 seconds)

# Before pushing (comprehensive)
make all          # All quality checks including tests
```

### CI Pipeline

```bash
# Stage 1: Fast feedback (on every commit)
make test-unit     # Unit tests
make lint          # Code quality
make type-check    # Type checking

# Stage 2: Comprehensive testing (on PR)
make test-integration  # Integration tests
make test-performance  # Performance benchmarks
make test-property     # Property-based tests
```

## Performance Considerations

### Unit Tests

- **Target**: < 1 second total execution time
- **Method**: Aggressive mocking of all external dependencies
- **Benefit**: Immediate feedback during development

### Integration Tests

- **Target**: < 3 minutes total execution time
- **Method**: Limited scope, efficient test data
- **Execution**: On-demand or in CI pipeline

### Optimization Tips

```bash
# Run specific test subsets for faster feedback
pytest tests/unit/test_vulnerability.py  # Single module
pytest -k "test_basic"                   # Pattern matching
pytest --maxfail=1                       # Stop on first failure

# Use parallelization for integration tests
pytest -n auto tests/integration/       # pytest-xdist
```

## Troubleshooting

### Common Issues

**Integration tests failing locally**:

- Ensure external tools are installed (solc, Z3)
- Check fixture file permissions
- Verify network connectivity for contract info tests

**Unit tests running slowly**:

- Check for missing mocks
- Look for accidental file I/O or network calls
- Use pytest profiling: `pytest --profile`

**Coverage gaps**:

- Run separate coverage for unit and integration: `make test-unit-cov` and `make test-integration-cov`
- Integration coverage may be lower - focus on unit test coverage

### Debugging Tests

```bash
# Verbose output
pytest -v -s tests/unit/test_module.py

# Debug specific test
pytest tests/unit/test_module.py::test_function -v -s --tb=long

# Profile slow tests
pytest --profile tests/unit/

# Interactive debugging
pytest --pdb tests/unit/test_module.py::test_function
```

## Manual Integration Testing

Manual testing with sample contracts verifies functionality after changes to core modules:

### Test Collections

- `samples/` - Main contracts with expected results (`.hex` bytecode)
- `bytecode_cgt/` - 3000+ real-world contracts (`.hex` and `.sol`)

### Key Test Commands

```bash
# Bytecode analysis
python oyente/oyente.py -s samples/SimpleDAO.hex -b
python oyente/oyente.py -s samples/EtherLotto.hex -b -j  # JSON output

# Solidity analysis (requires matching solc version)
solc-select use 0.6.2
python oyente/oyente.py -s bytecode_cgt/SimpleDAO/SimpleDAO.sol

# Error condition testing
echo "invalid_hex" > invalid.hex
python oyente/oyente.py -s invalid.hex -b
```

### After Module Changes

- **source_map.py**: Test with `-j` flag for JSON source references
- **symExec.py**: Test with `-v` flag on various contract types
- **analysis.py**: Verify vulnerability detection accuracy

## Best Practices Summary

1. **Fast Unit Tests**: Keep unit tests under 1 second total
2. **Clear Separation**: Don't mix unit and integration test logic
3. **Proper Mocking**: Mock all external dependencies in unit tests
4. **Meaningful Names**: Use descriptive test names and docstrings
5. **Test Categories**: Use markers to organize and run specific test types
6. **CI Integration**: Structure tests for fast feedback in development workflow
7. **Manual Verification**: Use sample contracts to verify functionality after major changes
8. **Version Management**: Use solc-select to test compatibility across Solidity versions
9. **Fixture Usage**: Use the centralized fixture registry for consistent test data
10. **Factory Patterns**: Leverage test data factories for realistic, varied test inputs

## Infrastructure Modernization

The test infrastructure has been modernized with:

- **Centralized Fixture Registry**: Single source of truth for all test fixtures
- **Test Data Factories**: Dynamic generation of realistic test data using factory patterns
- **Mock Consolidation**: Unified mock system with centralized registry
- **Static Asset Organization**: Contracts organized by category (safe/vulnerable/edge_cases)
- **Simplified Configuration**: Reduced complex setup from 300+ lines to ~15 lines

This testing structure provides fast development cycles with comprehensive coverage while maintaining clear separation between different test types.
