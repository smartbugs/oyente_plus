# Oyente+ Development Guide

## Development Workflow

```bash
# Format, lint, type-check, and test (run before commits)
make all && pre-commit run -a

# Individual commands
make format      # Format with Black
make lint        # Check with Ruff
make type-check  # Verify with mypy
make test        # Run unit tests (excludes integration)
make test-cov    # Run tests with coverage
```

## Testing

**Status**: 513 test functions executed with 100% pass rate across comprehensive test infrastructure

```bash
# Quick commands
make test          # Run unit tests only (default excludes integration)
make test-unit     # Unit tests only (explicit)
make test-integration  # Integration tests only
make test-cov      # Tests with coverage
make all          # Format, lint, type-check, test

# Running single tests
make test TEST=tests/unit/test_vulnerability.py           # Single test file
make test TEST=tests/unit/test_vulnerability.py::TestReentrancy  # Single test class
make test TEST=tests/unit/test_vulnerability.py::TestReentrancy::test_basic_detection  # Single test method

# Running single tests with coverage
make test-cov TEST=tests/unit/test_vulnerability.py       # Single file with coverage
```

**📋 For detailed testing guide**: See `docs/testing.md`

## Architecture Overview

### Core Components

- **`oyente/oyente.py`**: Main CLI entry point and configuration
- **`oyente/input_helper.py`**: Input handling for Solidity/bytecode using crytic-compile
- **`oyente/symExec.py`**: Symbolic execution engine with Z3 constraint solving
- **`oyente/vulnerability.py`**: Vulnerability detection classes (100% test coverage ✅)
- **`oyente/ast_helper.py`**: AST processing and contract analysis (comprehensive test coverage ✅)
- **`oyente/analysis.py`**: Analysis state management and vulnerability reporting

### Analysis Flow

1. **Input Processing**: Compile Solidity or parse bytecode
2. **CFG Construction**: Build control flow graph from EVM opcodes
3. **Symbolic Execution**: Explore paths with constraint solving
4. **Vulnerability Detection**: Apply security analysis patterns
5. **Report Generation**: Output findings with source mapping

### Supported Weaknesses

- **Reentrancy**: External call state manipulation
- **Integer Overflow/Underflow**: Arithmetic boundary violations
- **Timestamp Dependence**: Block timestamp manipulation
- **Callstack Attack**: Call depth limitations
- **Concurrency Issues**: Transaction ordering dependencies
- **Assertion Failures**: Solidity assert statement violations

## Development

### Project Status

**Completed**:
- **Code Quality**: 0 linting errors (fully resolved from 483)
- **Testing Infrastructure**: 513 tests with 100% pass rate
- **PEP 621 compliant packaging** with Poetry integration
- **Comprehensive pyproject.toml configuration** for all tools
- **Security-first code quality tooling** (Black, Ruff, mypy)
- **Complete test coverage** for core modules
- **Type hints** for 15 of 17 modules with comprehensive docstrings
- **Robust mocking infrastructure** for Z3, filesystem, and external dependencies
- **Critical Bug Fixes**: Major reliability improvements with 5+ critical bugs fixed
- **Type Safety**: 0 mypy errors - complete type coverage achieved
- **Pre-commit hooks**: Automated quality checks configured
- **CI/CD pipeline**: GitHub Actions with multi-stage testing and automation

### Code Quality Standards

All code must pass these checks before committing:

```bash
make all  # Runs format, lint, type-check, test
```

- **Black**: Code formatting (120 char lines)
- **Ruff**: Linting with security focus (Bandit rules)
- **mypy**: Static type checking
- **pytest**: Unit and integration testing

### Contributing Guidelines

1. **Setup Development Environment**:
   ```bash
   ./scripts/setup-venv.sh
   source venv/bin/activate
   ```

2. **Make Changes**: Follow existing code patterns and conventions

3. **Run Quality Checks**:
   ```bash
   make all  # Must pass before committing
   ```

4. **Add Tests**: All new functionality requires tests

5. **Documentation**: Update docstrings and README as needed

### Pre-commit Hooks

Automated quality checks run before each commit to ensure consistent code quality:

#### Setup

Pre-commit hooks are automatically installed when using the setup script:

```bash
./scripts/setup-venv.sh  # Installs and configures pre-commit hooks
```

Or install manually:

```bash
# Install pre-commit (included in dev dependencies)
poetry install --with dev

# Install the hooks (run once after cloning)
poetry run pre-commit install
```

#### What Runs Automatically

Each commit triggers:

- **File Checks**: Trailing whitespace, file endings, YAML/JSON/TOML syntax
- **Code Formatting**: `make format` (Black formatting)
- **Linting**: `make lint` (Ruff code quality checks)
- **Type Checking**: `make type-check` (mypy static analysis)
- **Unit Tests**: `make test-unit` (fast unit tests)
- **Integration Tests**: `make test-integration` (comprehensive tests)

#### Usage Tips

```bash
# Run manually on all files
poetry run pre-commit run --all-files

# Run specific hooks
poetry run pre-commit run format
poetry run pre-commit run test-unit

# Skip hooks (emergency only)
git commit --no-verify -m "emergency commit"
```

If any check fails, fix the issues and commit again. The hooks ensure all code meets quality standards before entering the repository.

## CI/CD Pipeline

### Streamlined Three-Stage Pipeline

The project uses a focused GitHub Actions pipeline with three essential stages:

#### **Pipeline Stages** (< 15 minutes total)

1. **Code Quality** (~5 minutes)
   - Black formatting validation
   - Ruff linting with security focus
   - mypy type checking (0 errors required)

2. **Unit Tests** (~5 minutes)
   - Matrix testing across Python 3.8-3.11
   - 513 test functions with 100% pass rate
   - Coverage reporting via Codecov

3. **Integration Tests** (~10 minutes)
   - Real Solidity compilation testing
   - End-to-end contract analysis validation
   - Sample contract verification

#### **Quality Gates**

All code must pass:
- ✅ 100% test success rate
- ✅ Zero linting errors
- ✅ Zero type checking errors
- ✅ >80% code coverage

#### **Development Integration**

```bash
# Local pipeline simulation (matches CI exactly)
make all              # Complete quality check

# Individual stages
make format lint type-check  # Code quality
make test-unit              # Unit tests
make test-integration       # Integration tests
```

**Pipeline Focus**: Streamlined for essential quality gates with fast feedback

### Automated Dependency Management

A separate workflow (`dependencies.yml`) handles dependency updates:

**Weekly Dependency Updates:**
- **Schedule:** Mondays at 8:00 AM UTC
- **Process:** Check outdated dependencies → Update → Test → Create PR
- **Validation:** Full quality checks using `make` targets
- **Output:** Automated pull requests with update summaries

**Manual Trigger:** Available via GitHub Actions UI

**Token Configuration:**
- Uses `GITHUB_TOKEN` (automatically provided by GitHub Actions)
- No manual configuration required
- Permissions: `contents: write`, `pull-requests: write`

## Performance & Benchmarks

### Performance Testing

Benchmark analysis performance:

```bash
python -m pytest tests/performance/ --benchmark-only
```

### Sample Contracts

The `samples/` directory contains test contracts including:
- `SimpleDAO.sol` - Reentrancy vulnerability
- `EtherLotto.sol` - Randomness issues
- `Government.sol` - Access control patterns

## Contributing

We welcome contributions! Please:

1. **Open an Issue**: Report bugs or suggest features on our [issue tracker](https://github.com/smartbugs/oyente_plus/issues)
2. **Submit PRs**: Feel free to send us a PR for changes you want to see!
3. **Follow Standards**: Ensure all quality checks pass with `make all`

### Development Setup

```bash
git clone https://github.com/smartbugs/oyente_plus.git
cd oyente_plus
./scripts/setup-venv.sh
source venv/bin/activate
make all  # Verify everything works
```
