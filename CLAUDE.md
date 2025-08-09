# CLAUDE.md

Guidance for Claude Code when working with this repository.

## 📋 Required Reading
- **`README.md`** - Setup, architecture, usage
- **`docs/PRD.yaml`** - Development roadmap and status  
- **`docs/testing.md`** - Testing guide (406+ tests)

## Project Status
- ✅ **Testing**: 492 tests (427 executed), 100% pass rate - COMPLETED
- ✅ **Code Quality**: 0 linting errors - COMPLETED  
- ✅ **Type Safety**: 15/17 modules typed, 0 mypy errors - COMPLETED
- ✅ **Critical Bugs**: 5 of 6 critical bugs FIXED ✅ (major progress!) - MOSTLY COMPLETED
- ❌ **CI/CD**: Not configured - TODO

## ⚠️ Recent Breaking Changes
- `vuln.name` changed from `"AssertionFailure"` to `"Assertion Failure"`

## Development Workflow

### Complete Development Cycle
```bash
# 1. DEVELOP: Implement feature/fix
#    - Add type hints and docstrings
#    - Follow naming conventions

# 2. CODE QUALITY & FORMATTING
make format       # Auto-format with Black
make lint         # Check with Ruff (fix any issues)
make type-check   # Verify with mypy (fix type errors)

# 3. TESTING
make test         # Run all unit & integration tests
#    - Add tests for new functionality
#    - Ensure 100% pass rate maintained

# 4. INTEGRATION VERIFICATION
make all          # Complete check: format + lint + type + test
python oyente/oyente.py -s tests/contracts/sample.sol  # Manual verification

# 5. DOCUMENTATION UPDATE (if needed)
#    - Update docs/*.md for user-facing changes
#    - Update docstrings for API changes

# 6. FINAL VALIDATION
make all          # Must pass 100% before commit
```

### Quick Commands
```bash
make all          # Complete workflow (MANDATORY before commits)
python oyente/oyente.py -s <contract.sol>  # Quick analysis

# If contract fails due to Solidity version mismatch:
solc-select use <version>  # Switch to required version (e.g., 0.8.19)
```

📋 **Details**: See `README.md` for setup/usage, `docs/testing.md` for testing, `docs/PRD.yaml` for roadmap

### Troubleshooting

**Version Compatibility Issues**: If a Solidity contract cannot be analyzed due to wrong compiler version, use `solc-select use <version>` to switch to the required version (e.g., `solc-select use 0.8.19`).

### Troubleshooting

**Version Compatibility Issues**: If a Solidity contract cannot be analyzed due to wrong compiler version, use `solc-select use <version>` to switch to the required version (e.g., `solc-select use 0.8.19`).

## Development Standards

### Code Quality Requirements

**MANDATORY before ANY changes:**
```bash
# Use make targets for comprehensive checks
make all          # Format, lint, type-check, test (before commits)
make format       # Format code with Black
make lint         # Check with Ruff  
make type-check   # Verify with mypy
make test         # Run all tests

# For checks on a subset of files only
ruff check oyente/file_to_edit.py
mypy oyente/file_to_edit.py
```

### Key Standards
- **Type hints**: All new code must have type annotations (complete type safety achieved ✅)
- **Security**: Never use `shell=True`, validate all inputs, fix hardcoded API key
- **Testing**: Add tests for all new functionality  
- **Documentation**: Google-style docstrings for public APIs
- **Critical Bugs**: File Path Resolution ✅, Stack Underflow ✅, Z3 Expression Exception ✅, LOG Opcodes Stack Validation ✅, and JUMP/JUMPI Address Conversion ✅ FIXED. Remaining: Source Map KeyError

## Essential Patterns

### Type Hints (Required)
```python
from typing import Dict, List, Optional, Protocol

def analyze_contract(
    source_code: str,
    timeout: int = 30,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, List[str]]:
    """Analyze smart contract for vulnerabilities."""
    pass
```

### Error Handling (Required)
```python
# ❌ BAD - Never use bare except
try:
    risky_operation()
except:
    pass

# ✅ GOOD - Specific exceptions
try:
    result = analyze_bytecode(bytecode)
except (ValueError, TypeError) as e:
    logger.error(f"Invalid bytecode format: {e}")
    raise AnalysisError(f"Bytecode analysis failed: {e}") from e
```

### Code Structure

**Limits**: Files <500 lines, functions <50 lines, complexity <10

**Naming**: 
- Classes: `PascalCase`
- Functions/variables: `snake_case` 
- Constants: `UPPER_SNAKE_CASE`

### Testing

📋 **Complete guide**: See `docs/testing.md`

**Test naming**: `test_<functionality>_<expected_result>`
**ALWAYS add tests** when modifying code

## Documentation Requirements

**Google-style docstrings required** for all public APIs:

```python
def analyze_contract(source_code: str, timeout: int = 120) -> Dict[str, List[str]]:
    """Analyze smart contract for vulnerabilities.
    
    Args:
        source_code: Solidity source code to analyze
        timeout: Maximum analysis time in seconds
        
    Returns:
        Dictionary mapping vulnerability types to warning messages
        
    Raises:
        AnalysisError: If compilation fails
        TimeoutError: If analysis exceeds timeout
    """
    pass
```

## Final Checklist

**Before ANY commit:**

1. `make all` - MUST pass completely
2. Add tests for new functionality  
3. Add type hints and docstrings
4. Never commit secrets or use `shell=True`

📋 **Complete references**: `README.md`, `docs/PRD.yaml`, `docs/testing.md`