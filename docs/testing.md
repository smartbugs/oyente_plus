# Testing Guide

This document explains the testing structure and workflows for Oyente+, covering unit tests, integration tests, and other testing types.

## Current Status

- **Total Tests**: 406+ test functions (342 unit + 64 integration) (405 passing, 1 skipped)
- **Pass Rate**: 99.8%
- **Test Files**: 14 comprehensive test files
- **Test Categories**: Unit (342), Integration (64), Property, Performance
- **Coverage**: Measurement currently blocked by technical issue, but all core modules have test coverage

## Test Organization

Following industry best practices, our tests are organized into distinct categories:

```
tests/
├── unit/           # Fast, isolated tests (10 test files, 342 tests)
├── integration/    # Component interaction tests (6 test files, 64 tests)
├── property/       # Hypothesis property-based tests
├── performance/    # Benchmark tests (pytest-benchmark)
├── fixtures/       # Test data and utilities
└── mocks/          # Mock objects (Z3, filesystem, subprocess, crytic-compile)
```

## Test Types

### Unit Tests (`tests/unit/`)

**Purpose**: Test individual functions and classes in isolation
**Test Count**: 342 test functions across 10 test files
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
**Test Count**: 90+ test functions across 6 test files
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
make test          # All tests (384+ tests, ~8 seconds)
make all          # Full quality checks including all tests

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

# By speed
pytest -m "not slow"     # Skip slow tests
pytest -m slow           # Only slow tests

# By dependencies
pytest -m requires_z3    # Tests requiring Z3 solver
pytest -m requires_solc  # Tests requiring Solidity compiler

# Combinations
pytest -m "unit and not slow"              # Fast unit tests only
pytest -m "integration and requires_solc"  # Integration tests with Solidity
```

## Test Configuration

### Default Behavior

- **pytest** (no arguments): Runs unit tests only
- Integration tests are excluded by default for fast development cycles
- Use explicit markers or directories to run integration tests

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

## Test Fixtures and Data

### Unit Test Fixtures (`tests/fixtures/`)

- Mock objects and test data for unit tests
- Generated test cases for mathematical functions
- Shared setup and teardown logic

### Integration Fixtures (`tests/integration/fixtures/`)

- Real Solidity contracts for testing
- EVM bytecode samples
- Expected analysis results (golden files)
- Contract samples covering different vulnerability types

**Structure**:
```
tests/integration/fixtures/
├── contracts/
│   ├── simple_safe.sol              # Basic safe contract
│   ├── reentrancy_vulnerable.sol    # Known vulnerable contract  
│   ├── reentrancy_safe.sol         # Properly protected contract
│   └── syntax_error.sol            # Invalid Solidity for error testing
├── bytecode/
│   ├── simple_contract.bin         # Basic bytecode
│   └── malformed.bin               # Invalid bytecode
└── expected/
    ├── reentrancy_vulnerable.json  # Expected analysis results
    └── reentrancy_safe.json        # Expected safe analysis
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

## Skipped Tests

The following tests are currently skipped in the test suite. This section documents which tests are skipped and the reasons for skipping them:

### Unit Tests

#### `tests/unit/test_input_helper.py`

**Skipped Test**: `TestInputHelperSolidityCompilation::test_compile_solidity_failure_exits`
- **File**: `tests/unit/test_input_helper.py:413`
- **Reason**: SystemExit test needs more work - temporarily skipped
- **Details**: This test attempts to verify that compilation failures result in a `sys.exit(1)` call, but the current implementation requires more sophisticated mocking to properly capture and test the SystemExit behavior without actually terminating the test process.
- **Impact**: Low - This is an edge case testing error handling behavior
- **Status**: Temporary skip, planned for future implementation

### Integration Tests

#### `tests/integration/test_compilation_workflow.py`

**Skipped Test**: `TestCryticCompileIntegration::test_compilation_failure_with_crytic_compile`
- **File**: `tests/integration/test_compilation_workflow.py:154`
- **Reason**: Test requires complex mocking that conflicts with module imports
- **Details**: This integration test attempts to mock crytic-compile failures, but the mocking approach conflicts with the module import system used by crytic-compile, causing test instability.
- **Impact**: Medium - This tests an important error handling path in the compilation workflow
- **Status**: Temporary skip, requires refactoring of the test approach

### Summary

- **Total Skipped Tests**: 2
- **Unit Tests Skipped**: 1
- **Integration Tests Skipped**: 1
- **Current Pass Rate**: 99.5% (405 passing, 1 skipped out of 406 total)

### Future Work

Both skipped tests are marked as temporary and are planned for implementation:

1. **SystemExit Testing**: Research and implement proper patterns for testing `sys.exit()` calls without terminating the test runner
2. **Crytic-Compile Mocking**: Refactor the integration test to use a different approach that doesn't conflict with module imports, possibly using fixture-based error injection

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

This testing structure provides fast development cycles with comprehensive coverage while maintaining clear separation between different test types.