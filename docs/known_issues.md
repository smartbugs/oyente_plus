# Known Issues in Oyente+

## Status Overview

**Critical Bugs**: 1 of 5 **FIXED** ✅ | **Success Rate**: ~25% on real contracts | **Production Ready**: No

## Critical Issues (Tool Failure)

### 1. ~~File Path Resolution Bug~~ - **FIXED** ✅
- **Location**: `oyente/symExec.py:1682, 1714`
- **Issue**: FileNotFoundError when `.hex.evm.disasm` files don't match expected `.hex.evm` pattern
- **Fix**: New `resolve_evm_bytecode_file()` function with proper path handling and file validation
- **Test**: `python oyente/oyente.py -b -s bytecodes_cgt/A/A.hex` ✅

### 2. Stack Underflow Bug
- **Location**: `oyente/symExec.py:2325` (SELFDESTRUCT + 30+ other opcodes)
- **Issue**: `IndexError: pop from empty list` when opcodes pop without stack validation
- **Test**: `echo "FF" > /tmp/test.hex && python oyente/oyente.py -b -s /tmp/test.hex`

### 3. Z3 Expression Exception Bug
- **Location**: `oyente/symExec.py:2004`
- **Issue**: `Z3Exception: Z3 expression expected` when simplifying non-Z3 expressions
- **Test**: `python oyente/oyente.py -b -s bytecodes_cgt/Alluma/Alluma.hex`

### 4. Systematic Stack Underflow Pattern
- **Location**: Multiple locations (30+ instances)
- **Issue**: Inconsistent stack depth validation across opcodes
- **Impact**: Multiple crash vectors with crafted bytecode

### 5. Source Map KeyError Pattern
- **Location**: `oyente/source_map.py:203`
- **Issue**: Path resolution fails for most Solidity files
- **Impact**: Tool largely broken for .sol analysis

## Medium Issues (Misleading Results)

### Error Handling
- Invalid inputs produce misleading results instead of failing clearly
- Users can't distinguish "no vulnerabilities" from "analysis failed"

### Solidity Compatibility
- Legacy contracts fail with outdated syntax (`function()` vs `fallback()`)
- Strict version matching prevents analysis of compatible contracts

### Security Issues
- **Hardcoded API Key**: `oyente/ethereum_data.py:20` exposes Etherscan key
- **Assertion Flag Bug**: `-a -b` combination crashes with unhelpful error

### Z3 Solver Issues
- Incomplete exception handling causes unhandled Z3Exceptions
- Solver cancellation produces unreliable results

## Low Issues (Usability)

- Inconsistent output formats and coverage reporting
- Broad exception handling masks specific errors  
- Confusing exit codes (vulnerabilities vs failures both return 1)
- Remote URL processing accepts non-Solidity content

## Testing Results

**Datasets Tested**: 250+ contracts from `bytecodes_cgt` and `bytecodes_skelcodes_selection`

**Success Rates by Type**:
- .hex files: ~80-85%
- .rt.hex files: ~75-80%  
- .sol files: ~40-60% (version issues)

**Critical Bug Impact**: All 5 critical bugs confirmed across diverse contract samples

## Recommended Fix Priority

1. **Critical bugs first** (4 remaining): Stack validation, Z3 expressions, source map processing
2. **Medium issues**: Error handling, security, compatibility
3. **Low issues**: Usability and consistency improvements

**Estimated Effort**: 4-5 days for remaining critical bugs

## Quick Reproduction Commands

```bash
# Stack Underflow Bug
echo "FF" > /tmp/test.hex && python oyente/oyente.py -b -s /tmp/test.hex

# File Path Resolution (FIXED)
python oyente/oyente.py -b -s bytecodes_cgt/A/A.hex

# Assertion Flag Bug
python oyente/oyente.py -a -b -s /tmp/test.hex

# Z3 Expression Bug
python oyente/oyente.py -b -s bytecodes_cgt/Alluma/Alluma.hex
```