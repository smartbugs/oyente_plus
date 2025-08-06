# Unit Testing - Gap Closure Plan

## Current Status
- ✅ **406+ tests** (99.8% pass rate) with comprehensive mocking infrastructure
- ❌ **5 key modules** lack test files: `oyente.py`, `source_map.py`, `opcodes.py`, `ethereum_data.py`, `batch_run.py`
- ❌ **Coverage measurement blocked** by configuration issue

## Target: 450+ tests with >90% coverage for all modules



# PHASE 1: CRITICAL (2-3 weeks)

## Task 1.1: CLI Testing (`oyente.py`)
**Goal**: `tests/unit/test_oyente.py` with 20+ tests

- [ ] Dependency validation: `cmd_exists()`, `has_dependencies_installed()`
- [ ] Version comparison logic: `compare_versions()`  
- [ ] Bytecode analysis workflow: `analyze_bytecode()`
- [ ] Solidity analysis orchestration: `run_solidity_analysis()`, `analyze_solidity()`
- [ ] Main CLI entry point: `main()` argument parsing and exit codes

## Task 1.2: Source Mapping (`source_map.py`)
**Goal**: `tests/unit/test_source_map.py` with 25+ tests

- [ ] `Source` class: file loading, content parsing, line break positions
- [ ] `SourceMap` initialization: Solidity and Standard JSON modes
- [ ] Source extraction: `get_source_code_from_pc()`, `get_buggy_line()`
- [ ] Location conversion: `get_location()`, position-to-line mapping
- [ ] AST integration: variable/function name extraction

## Task 1.3: Coverage Fix
**Goal**: Working `make test-cov` with baseline metrics

- [ ] Debug pytest-cov configuration issue
- [ ] Generate coverage report for existing tests
- [ ] Integrate coverage into development workflow

---

# PHASE 2: EVM OPERATIONS (1-2 weeks)

## Task 2.1: Opcode Testing (`opcodes.py`)
**Goal**: `tests/unit/test_opcodes.py` with 15+ tests

- [ ] Opcode data retrieval: `get_opcode()` for all EVM opcodes
- [ ] Gas cost calculations: `get_ins_cost()` for different operation types
- [ ] Data structure integrity: validate opcode definitions

## Task 2.2: Enhanced Integration Tests
**Goal**: End-to-end CLI and source mapping validation

- [ ] CLI workflows: bytecode/Solidity analysis with real contracts
- [ ] Source mapping integration: vulnerability location accuracy

---

# PHASE 3: UTILITIES (1 week)

## Task 3.1: Ethereum Data (`ethereum_data.py`)
**Goal**: `tests/unit/test_ethereum_data.py` with 12+ tests

- [ ] API methods: `getBalance()`, `getCode()`, `getStorageAt()`
- [ ] Error handling: network timeouts, invalid responses
- [ ] Mock all API calls (no actual network requests)

## Task 3.2: Batch Processing (`batch_run.py`)
**Goal**: `tests/unit/test_batch_run.py` with 8+ tests

- [ ] Batch logic: contract loading, job distribution, result aggregation
- [ ] Mock all subprocess calls and file operations

---

# PHASE 4: PERFORMANCE (1 week)

## Task 4.1: Benchmarks
**Goal**: Performance baselines and regression detection

- [ ] Establish baselines: analysis speed, memory usage
- [ ] Configure performance thresholds and CI integration

## Task 4.2: Property-Based Testing
**Goal**: Enhanced edge case coverage with Hypothesis

- [ ] Input validation: bytecode parsing, source mapping
- [ ] Symbolic execution invariants and solver consistency

---

# SUCCESS METRICS

## Targets
- **450+ tests** (from current 406+) with >99% pass rate
- **100% module coverage** - all modules have test files  
- **>90% line coverage** with working measurement

## Completion Criteria

### Phase 1: Critical Infrastructure ✅
- [ ] `test_oyente.py` (20+ tests) - CLI interface
- [ ] `test_source_map.py` (25+ tests) - vulnerability reporting  
- [ ] Working coverage measurement

### Phase 2: EVM Operations ✅  
- [ ] `test_opcodes.py` (15+ tests) - gas calculations
- [ ] Enhanced integration tests

### Phase 3: Utilities ✅
- [ ] `test_ethereum_data.py` (12+ tests) - API integration
- [ ] `test_batch_run.py` (8+ tests) - batch processing

### Phase 4: Performance ✅
- [ ] Performance baselines established
- [ ] Property-based testing expanded

## Implementation Notes
- **Use existing patterns**: Leverage comprehensive mocking infrastructure
- **Incremental approach**: Complete one task before moving to next
- **Maintain quality**: >99% pass rate throughout implementation