# Code Quality TODO List

*Generated: 2025-07-27*
*Based on analysis of codebase with 535 Ruff errors and 1008+ MyPy errors*

## Overview

This document tracks the systematic resolution of code quality issues across the Oyente+ codebase. The project currently has comprehensive test infrastructure (338 test functions) but needs significant code quality improvements in the main modules.

## Critical Priority Files 🚨

### 1. `oyente/symExec.py` - **MOST CRITICAL**
- **Status**: ❌ Not Started
- **Size**: 2,730 lines (largest file)
- **Issues**: 899 MyPy errors + 432 Ruff errors (81% of all linting issues)
- **Blockers**: 
  - 329 F405 errors (undefined star imports)
  - 28 N806 errors (non-lowercase variables)
  - 14 unused variables
  - Security issues (S110, S301)
- **Action Plan**:
  - [ ] Replace star imports with explicit imports
  - [ ] Fix variable naming conventions
  - [ ] Remove unused variables
  - [ ] Add comprehensive type hints
  - [ ] Break into smaller modules (current 2730 lines → target <500 per module)

### 2. `oyente/analysis.py` - **HIGH PRIORITY**
- **Status**: ❌ Not Started  
- **Size**: 438 lines
- **Issues**: 23 MyPy errors + 23 Ruff errors
- **Blockers**:
  - F405 errors (undefined `get_vars`, star imports)
  - Missing type annotations
- **Action Plan**:
  - [ ] Fix star import issues
  - [ ] Add type hints for all functions
  - [ ] Resolve undefined function references

### 3. `oyente/source_map.py` - **HIGH PRIORITY**
- **Status**: ❌ Not Started
- **Size**: 238 lines  
- **Issues**: 58 MyPy errors + 12 Ruff errors
- **Blockers**:
  - RUF012 (mutable class attributes need ClassVar)
  - E722 (bare except clauses)
- **Action Plan**:
  - [ ] Fix mutable class attributes with `typing.ClassVar`
  - [ ] Replace bare except clauses with specific exceptions
  - [ ] Add comprehensive type hints

## Medium Priority Files 📋

### 4. `oyente/input_helper.py` - **P0 PRIORITY per CLAUDE.md**
- **Status**: ❌ Not Started
- **Size**: 652 lines (2nd largest)
- **Issues**: Missing type hints (P0 priority)
- **Action Plan**:
  - [ ] Add comprehensive type hints
  - [ ] Audit for potential Ruff issues
  - [ ] Improve error handling patterns

### 5. `oyente/test_evm/evm_unit_test.py`
- **Status**: ❌ Not Started
- **Issues**: 32 Ruff errors (F403/F405 star imports)
- **Action Plan**:
  - [ ] Replace star imports with explicit imports
  - [ ] Consider moving to tests/ directory structure

### 6. `oyente/run_tests.py`
- **Status**: ❌ Not Started
- **Issues**: 12 MyPy + 13 Ruff errors
- **Blockers**: E402 (imports not at top), missing type annotations
- **Action Plan**:
  - [ ] Move imports to top of file
  - [ ] Add return type annotations
  - [ ] Consider deprecating in favor of pytest/Makefile

## Lower Priority Files 📝

### 7. `oyente/batch_run.py`
- **Status**: ❌ Not Started
- **Issues**: 2 MyPy + 7 Ruff errors
- **Blockers**: SIM115 (file context), S605/S607 (subprocess security)
- **Action Plan**:
  - [ ] Use context managers for file operations
  - [ ] Fix subprocess security issues

### 8. `oyente/ethereum_data.py`
- **Status**: ❌ Not Started  
- **Issues**: 4 MyPy + 12 Ruff errors
- **Blockers**: N802/N806 (naming), UP031 (printf formatting)
- **Action Plan**:
  - [ ] Fix function and variable naming conventions
  - [ ] Update string formatting to f-strings

### 9. `oyente/ethereum_data1.py`
- **Status**: ❌ Not Started
- **Issues**: 7 MyPy + 2 Ruff errors
- **Action Plan**:
  - [ ] Fix function naming (N802 errors)
  - [ ] Add type annotations

### 10. `oyente/ast_walker.py`
- **Status**: ❌ Not Started
- **Issues**: 3 MyPy errors (unreachable statements)
- **Action Plan**:
  - [ ] Remove unreachable code
  - [ ] Audit control flow logic

## Already Clean Files ✅

These files have **zero or minimal issues** (per CLAUDE.md):
- ✅ `oyente/oyente.py` (2 minor security warnings only)
- ✅ `oyente/opcodes.py` 
- ✅ `oyente/global_params.py`
- ✅ `oyente/basicblock.py`
- ✅ `oyente/vargenerator.py`
- ✅ `oyente/vulnerability.py`

## Error Summary by Category

### Ruff Linting Errors (535 total)
- **373 F405**: undefined-local-with-import-star-usage ⚠️ **CRITICAL**
- **32 N806**: non-lowercase-variable-in-function
- **17 UP031**: printf-string-formatting
- **16 F841**: unused-variable
- **14 SIM108**: if-else-block-instead-of-if-exp
- **11 SIM102**: collapsible-if
- **9 E402**: module-import-not-at-top-of-file
- **9 E722**: bare-except ⚠️ **SECURITY RISK**
- **8 SIM115**: open-file-with-context-handler
- **Security issues**: S603, S607, S110, S301, S605 ⚠️ **SECURITY RISK**

### MyPy Type Errors (1008+ total)
- **899**: `oyente/symExec.py` (89% of all errors)
- **58**: `oyente/source_map.py`
- **23**: `oyente/analysis.py`
- **12**: `oyente/run_tests.py`
- **Others**: Various files with <10 errors each

## Execution Strategy

### Phase 1: Foundation (Weeks 1-2)
1. **Start with `symExec.py`** - Highest impact (81% of errors)
2. **Fix critical star import issues** (F405/F403 errors)
3. **Add basic type hints to core functions**

### Phase 2: Core Modules (Weeks 3-4)  
1. **Complete `analysis.py` and `source_map.py`**
2. **Add type hints to `input_helper.py`** (P0 priority)
3. **Fix security issues** (S-codes) across all files

### Phase 3: Cleanup (Week 5)
1. **Address remaining medium/low priority files**
2. **Remove unused variables and unreachable code**
3. **Modernize string formatting and naming**

### Phase 4: Validation (Week 6)
1. **Run comprehensive quality checks**
2. **Ensure all tests still pass**
3. **Verify performance hasn't regressed**

## Success Metrics

- **Target**: Zero critical errors (F405, E722, S-codes)
- **Goal**: <50 total Ruff errors (90% reduction)
- **Goal**: <100 total MyPy errors (90% reduction)
- **Requirement**: All 338 tests continue passing
- **Requirement**: No performance regression >5%

## Commands for Tracking Progress

```bash
# Check overall progress
ruff check oyente/ --statistics
mypy oyente/ --show-error-codes | wc -l

# Check specific file
ruff check oyente/symExec.py
mypy oyente/symExec.py

# Verify tests still pass
make test

# Full quality check
make all
```

## Notes

- **Security First**: All S-codes (security issues) are high priority regardless of file
- **Test Coverage**: Current 2.4% coverage provides safety net for refactoring
- **Incremental Approach**: Fix one file at a time to maintain stability
- **Documentation**: Update this file as progress is made

---

*This TODO list should be updated as files are completed and new issues are discovered.*