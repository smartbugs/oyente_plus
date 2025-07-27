# Oyente+ Code Architecture

## Overview

Oyente+ is a modernized symbolic execution tool for Ethereum smart contract security analysis. The codebase has been significantly refactored from the original Oyente to support modern Python practices, comprehensive testing, and maintainable architecture.

## Core Modules

### *oyente.py* - Main Entry Point

**Purpose**: Command-line interface and orchestration of the analysis pipeline.

**Key Features**:
- Multi-format input support (Solidity source, EVM bytecode, remote contracts)
- Configuration management via `global_params.py`
- Integration with modern compilation tools (crytic-compile)
- Error handling and result formatting

**Input Types**:
- **Solidity files** (`-s contract.sol`)
- **EVM bytecode** (`-s bytecode_file -b`) 
- **Remote contracts** (`-ru URL`)
- **Assertion checking** (`-a` flag for Solidity assert verification)

**Workflow**:
1. Parse command-line arguments and validate inputs
2. Configure analysis parameters (timeouts, depth limits, etc.)
3. Delegate to `input_helper.py` for compilation/preprocessing
4. Invoke `symExec.py` for symbolic execution analysis
5. Format and output vulnerability reports

### *input_helper.py* - Input Processing & Compilation

**Purpose**: Handle diverse input formats and prepare bytecode for analysis.

**Key Components**:
- **Solidity Compilation**: Integration with `solc` and `crytic-compile`
- **Bytecode Parsing**: Direct EVM bytecode processing
- **Remote Fetching**: Download and compile remote contracts
- **Source Mapping**: Maintain source-to-bytecode mappings for error reporting

**Modern Improvements**:
- Uses `crytic-compile` for robust Solidity compilation
- Support for latest Solidity versions
- Better error handling for compilation failures
- Improved source mapping generation

### *symExec.py* - Symbolic Execution Engine

**Purpose**: Core symbolic execution engine using Z3 constraint solving.

**Architecture**:
```
build_cfg_and_analyze()
├── collect_vertices()     # Identify basic blocks
├── construct_bb()         # Build control flow graph  
├── full_sym_exec()        # Execute symbolic analysis
│   └── sym_exec_ins()     # Process individual opcodes
└── vulnerability_checks() # Apply security analysis
```

**Key Functions**:
- **CFG Construction**: Parse disassembled bytecode into basic blocks
- **Symbolic State Management**: Track stack, memory, storage symbolically
- **Path Exploration**: Explore execution paths with constraint solving
- **Z3 Integration**: Generate and solve logical constraints

**Opcode Categories**:
- **0x00-0x0f**: Arithmetic and stop operations
- **0x10-0x1f**: Comparison and bitwise logic  
- **0x20**: SHA3 hashing (modeled symbolically)
- **0x30-0x3f**: Environmental information (address, balance, etc.)
- **0x40-0x4f**: Block information (timestamp, number, etc.)
- **0x50-0x5f**: Stack, memory, storage operations
- **0x60-0x6f**: Push operations
- **0x80-0x8f**: Duplication operations
- **0x90-0x9f**: Exchange operations
- **0xa0-0xa4**: Logging operations
- **0xf0-0xff**: System operations (call, create, return, etc.)

**Modern EVM Support**:
- **PUSH0** (0x5f): Zero push operation
- **TLOAD/TSTORE**: Transient storage operations
- **Latest opcodes**: Support for recent EVM updates

**State Management**:
```python
class SymbolicState:
    stack: List[Any]           # EVM stack (max 1024 items)
    memory: List[Any]          # Expandable memory array
    storage: Dict[Any, Any]    # Persistent storage mapping
    pc: int                    # Program counter
    gas: int                   # Gas consumption tracking
    path_conditions: List[Any] # Z3 constraints for current path
```

**Control Flow Analysis**:
- **Basic Blocks**: Identified by jump destinations and terminators
- **Edge Detection**: Dynamic discovery during symbolic execution
- **Path Explosion Mitigation**: Configurable depth limits and timeouts

### *vulnerability.py* - Security Analysis (✅ **27+ Tests Complete**)

**Purpose**: Implement vulnerability detection patterns for smart contract security.

**Architecture**: All vulnerability detectors inherit from base `Vulnerability` class:

```python
class Vulnerability:
    def __init__(self, source_map, pcs):
        self.source_map = source_map      # Source code mapping
        self.pcs = pcs                    # Program counters where found
        self.warnings = []                # Formatted warning messages
    
    def is_vulnerable(self) -> bool:      # Check if vulnerable
    def get_warnings(self) -> List[str]:  # Get formatted warnings
```

**Implemented Detectors**:

1. **Reentrancy (`ReentrancyDetector`)**:
   - Detects external calls that allow contract re-entry
   - Tracks state modifications after external calls
   - Identifies missing reentrancy guards

2. **Integer Overflow (`IntegerOverflow`)**:
   - Detects arithmetic operations that can overflow/underflow
   - Models 256-bit integer boundaries
   - Considers SafeMath usage patterns

3. **Timestamp Dependence (`TimestampDependency`)**:
   - Identifies reliance on block.timestamp
   - Detects timestamp manipulation vulnerabilities
   - Tracks temporal ordering assumptions

4. **Callstack Attack (`CallstackDepthAttack`)**:
   - Detects calls without proper return value checking
   - Identifies vulnerable call patterns
   - Checks for recommended defensive patterns

5. **Concurrency Issues (`ConcurrencyBug`)**:
   - Tracks value transfers across different execution paths
   - Identifies transaction ordering dependencies
   - Detects race conditions in state updates

6. **Assertion Failures (`AssertionFailure`)**:
   - Analyzes Solidity assert() statements
   - Tracks paths leading to INVALID opcodes
   - Distinguishes assert failures from other INVALID causes

**Security Analysis Process**:
```
For each execution path:
├── Track external calls and state changes
├── Analyze arithmetic operations for overflow
├── Check timestamp dependencies in conditions  
├── Validate call return values
├── Detect concurrent access patterns
└── Verify assertion reachability
```

### *analysis.py* - Analysis State Management

**Purpose**: Coordinate vulnerability analysis and maintain execution state.

**Key Components**:
- **Global State Tracking**: Maintain contract state across execution paths
- **Vulnerability Orchestration**: Coordinate multiple vulnerability detectors
- **Result Aggregation**: Collect and format analysis results
- **Performance Monitoring**: Track analysis metrics and timeouts

### *basicblock.py* - Control Flow Graph

**Purpose**: Represent and manage basic blocks in the control flow graph.

**BasicBlock Class**:
```python
class BasicBlock:
    def __init__(self, start_address, end_address):
        self.start = start_address       # First instruction address
        self.end = end_address          # Last instruction address  
        self.instructions = []           # List of opcodes in block
        self.jump_target = None         # Target for unconditional jumps
        self.conditional_jump = None    # Target for conditional jumps
        self.fall_through = None        # Next sequential block
```

**CFG Construction Process**:
1. **Identify Block Boundaries**: `JUMPDEST`, `JUMP`, `JUMPI`, `STOP`, `RETURN`, `REVERT`
2. **Parse Instructions**: Extract opcodes and operands for each block
3. **Build Edges**: Connect blocks based on jump relationships
4. **Validate Structure**: Ensure CFG completeness and consistency

## Supporting Modules

### *vargenerator.py* - Symbolic Variable Generation

**Purpose**: Generate unique symbolic variables for Z3 constraint solving.

**Features**:
- **Unique Naming**: Ensure variable name uniqueness across analysis
- **Type Management**: Handle different variable types (BitVec, Bool, etc.)
- **Scope Tracking**: Manage variable scopes and lifetimes

### *source_map.py* - Source Code Mapping

**Purpose**: Map bytecode addresses back to source code locations.

**Capabilities**:
- **Source Line Mapping**: Connect bytecode to original Solidity lines
- **Error Reporting**: Provide precise source locations for vulnerabilities
- **Compiler Integration**: Work with various Solidity compiler versions

### *global_params.py* - Configuration Management

**Purpose**: Centralized configuration and parameter management.

**Configuration Options**:
- **Analysis Limits**: Timeout values, maximum depth, loop bounds
- **Solver Settings**: Z3 configuration and optimization settings  
- **Output Formatting**: Verbose modes, report formats
- **Debug Options**: Logging levels, intermediate output

## Testing Infrastructure

Oyente+ features a comprehensive testing framework with multiple test categories:

### Modern Test Suite (`tests/` directory)

**Architecture**:
```
tests/
├── unit/           # Fast, isolated unit tests (27+ tests ✅)
├── integration/    # Component interaction tests
├── property/       # Hypothesis property-based tests
├── performance/    # Benchmark tests with pytest-benchmark
├── fixtures/       # Test data generators and utilities
└── mocks/          # Mock objects (Z3, filesystem, subprocess)
```

**Testing Tools**:
- **pytest**: Modern test runner with extensive plugin ecosystem
- **Hypothesis**: Property-based testing for edge case discovery
- **pytest-cov**: Code coverage reporting (90% threshold)
- **pytest-benchmark**: Performance regression detection
- **Factory Boy**: Test data generation
- **pytest-mock**: Advanced mocking capabilities

**Test Categories**:
- **Unit Tests**: Individual function/class testing with 100% `vulnerability.py` coverage
- **Integration Tests**: Multi-component interaction testing
- **Property Tests**: Automated edge case generation with Hypothesis
- **Performance Tests**: Regression testing for analysis speed

**Test Execution**:
```bash
# Modern test suite (preferred)
make test                               # All tests
make test TEST=tests/unit/test_file.py  # Specific test file
make test-cov                           # With coverage reporting
make test-legacy                        # Legacy EVM tests

# Direct pytest commands (alternative)
python -m pytest tests/ -v             # All tests
python -m pytest tests/unit/           # Unit tests only
python -m pytest tests/ --cov=oyente --cov-report=html  # Coverage
```

### Legacy EVM Test Suite

**Purpose**: Validate EVM opcode implementation against Ethereum test vectors.

**Components**:
- **`run_tests.py`**: Main test orchestrator
- **`evm_unit_test.py`**: EVM state comparison utilities
- **`test_evm/test_data/`**: JSON test vectors from Ethereum test suite

**Test Process**:
1. Load JSON test data with expected EVM states
2. Execute symbolic analysis on test bytecode
3. Compare final states (storage, memory, gas consumption)
4. Report discrepancies and implementation bugs

**Test Data Sources**:
- [Ethereum VM Tests](https://github.com/ethereum/tests/tree/develop/VMTests)
- Custom test cases for Oyente-specific functionality
- Real-world contract samples in `samples/` directory

## Development Status & Roadmap

### ✅ **Completed (Phase 1)**
- **Comprehensive Unit Testing**: 27+ tests for `vulnerability.py` with 100% coverage
- **Modern Python Tooling**: Black, Ruff, mypy, pytest configuration
- **Poetry Integration**: Modern dependency management and packaging
- **Code Quality Infrastructure**: Makefile automation, pre-commit ready
- **Type Safety**: Complete type hints for vulnerability detection module

### 🔄 **In Progress (Phase 2)**
- **Type Annotation Expansion**: Adding type hints to `oyente.py`, `input_helper.py`, `analysis.py`
- **Linting Resolution**: Fixing 659 remaining linting issues in main codebase
- **Test Coverage Expansion**: Unit tests for `symExec.py` core functions
- **Documentation Improvement**: Comprehensive docstring coverage

### 📋 **Planned (Phase 3)**
- **Architectural Refactoring**: Breaking down monolithic `symExec.py` (5800+ lines)
- **Plugin Architecture**: Modular vulnerability detector system
- **Performance Optimization**: 50% analysis speed improvement target
- **CI/CD Pipeline**: Automated testing and deployment infrastructure

### 🎯 **Success Metrics**
- **Code Quality**: 90% test coverage, zero critical security issues
- **Type Safety**: 95% type annotation coverage
- **Performance**: 50% faster analysis, 30% less memory usage
- **Developer Experience**: <10 minute setup time, <15 minute CI pipeline

## Key Design Principles

1. **Security First**: All code changes must pass security linting (Bandit)
2. **Type Safety**: Gradual migration to full type annotation coverage  
3. **Test-Driven**: New features require corresponding tests
4. **Performance Aware**: Monitor and optimize analysis bottlenecks
5. **Modern Python**: Leverage Python 3.8+ features and best practices
