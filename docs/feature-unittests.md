# Unit Testing - Gap Closure Plan

## Current Status
- ✅ **406+ tests** (99.8% pass rate) with comprehensive mocking infrastructure
- ❌ **5 key modules** lack test files: `oyente.py`, `source_map.py`, `opcodes.py`, `ethereum_data.py`, `batch_run.py`
- ❌ **Coverage measurement blocked** by configuration issue
- ⚠️ **16 bugs discovered** (5 critical) through testing - must fix before adding more tests

## Target: Fix critical bugs first, then achieve 450+ tests with >90% coverage



# PHASE 0: BUG FIXES (URGENT - 1-2 weeks)

## Critical Bugs to Fix First
- [ ] **Source Map KeyError** (`source_map.py:203,254`) - Breaks all .sol analysis
- [ ] **Z3 Expression Exception** (`symExec.py:2004`) - Crashes on certain bytecode
- [ ] **Stack Underflow** (`symExec.py:30+ locations`) - Missing validation causes crashes
- [ ] **Hardcoded API Key** (`ethereum_data.py:20`) - Security vulnerability

# PHASE 1: TESTING (After bug fixes - 2-3 weeks)

## Task 1.1: CLI Testing (`oyente.py`) - 20+ tests
## Task 1.2: Source Mapping (`source_map.py`) - 25+ tests  
## Task 1.3: Coverage Fix - Debug pytest-cov configuration

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

### Phase 0: Bug Fixes (URGENT) ⚠️
- [ ] Critical bugs resolved - tool functional for basic analysis
- [ ] Security vulnerabilities patched  
- [ ] Tool success rate >50% on standard contracts

### Phases 1-4: Testing & Performance ✅
- [ ] 450+ total tests with >99% pass rate
- [ ] All modules have test files
- [ ] Working coverage measurement >90%
- [ ] Performance baselines established

## Implementation Notes
- **Priority**: Fix critical bugs before adding more tests
- **Use existing patterns**: Leverage comprehensive mocking infrastructure
- **Maintain quality**: >99% pass rate throughout implementation