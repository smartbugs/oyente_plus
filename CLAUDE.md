# CLAUDE.md

Guidance for Claude Code when working with this repository.

## 📋 Required Reading
- **`README.md`** - Setup, architecture, usage
- **`docs/PRD.yaml`** - Development roadmap and status  
- **`docs/testing.md`** - Testing guide (406+ tests)

## Project Status
- ✅ **Testing**: 425+ tests executed, 100% pass rate - COMPLETED
- ✅ **Code Quality**: 0 linting errors - COMPLETED  
- 🔄 **Type Safety**: 15/17 modules typed, 178 mypy errors remain - IN PROGRESS
- 🔄 **Critical Bugs**: 2 of 5 critical bugs FIXED, 3 remaining - IN PROGRESS
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
```

📋 **Details**: See `README.md` for setup/usage, `docs/testing.md` for testing

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
- **Type hints**: All new code must have type annotations (178 mypy errors to fix)
- **Security**: Never use `shell=True`, validate all inputs, fix hardcoded API key
- **Testing**: Add tests for all new functionality  
- **Documentation**: Google-style docstrings for public APIs
- **Critical Bugs**: File Path Resolution ✅ and Stack Underflow ✅ FIXED. Remaining: Z3, Source Map, and systematic stack validation

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
