# Oyente+

An Analysis Tool for Smart Contracts

[![License: GPL v3][license-badge]][license-badge-url]
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![Code style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

*This repository is currently maintained by Thomas Fenninger ([@zariliv](https://github.com/zariliv)). If you encounter any bugs or usage issues, please feel free to create an issue on [our issue tracker](https://github.com/smartbugs/oyente_plus/issues).*

**Oyente+** is a modernized version of the original Oyente symbolic execution tool for Ethereum smart contracts. It performs comprehensive security analysis to detect vulnerabilities including reentrancy, integer overflow, timestamp dependence, and more.

## ✨ Features

- **Symbolic Execution**: Deep analysis using Z3 constraint solving
- **Multi-format Support**: Analyze Solidity source code, EVM bytecode, or remote contracts
- **Modern Python**: Built for Python 3.8+ with comprehensive type hints
- **Comprehensive Testing**: 27+ unit tests with property-based testing
- **Code Quality**: Enforced with Black, Ruff, mypy, and pytest
- **Latest EVM Support**: Compatible with recent opcodes (PUSH0, TLOAD, TSTORE)

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (excluding 3.12.0) - Modern type hints and features
- **[Poetry](https://python-poetry.org/)** - PEP 621 compliant dependency management  
- **[Solidity compiler (solc)](https://docs.soliditylang.org/en/latest/installing-solidity.html)** - Contract compilation
- **[Go Ethereum (geth)](https://geth.ethereum.org/downloads/)** - EVM execution engine

### Installation

#### Option 1: Using Make (Recommended)

```bash
# Clone the repository
git clone https://github.com/smartbugs/oyente_plus.git
cd oyente_plus

# Setup development environment with all dependencies
make setup

# Activate virtual environment (if using Poetry outside venv)
poetry shell
```

#### Option 2: Manual Setup

```bash
# Install all dependencies (development, testing, linting)
poetry install --with dev,test,lint

# Install specific dependency groups
poetry install --with dev    # Development tools only
poetry install --with test   # Testing framework only  
poetry install --with lint   # Linting tools only

# Production installation only
poetry install --only main
```

#### Option 3: Docker

```bash
docker pull smartbugs/oyente_plus
docker run -it smartbugs/oyente_plus
```

### System Dependencies

#### Solidity Compiler

```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc

# Or use solc-select for version management
solc-select install latest
solc-select use latest
```

#### Go Ethereum (for EVM execution)

```bash
# Ubuntu/Debian
sudo apt-get install software-properties-common
sudo add-apt-repository -y ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install ethereum

# Or download from https://geth.ethereum.org/downloads/
```

## 🔧 Usage

### Command Line Interface

```bash
# Analyze Solidity contract
python oyente/oyente.py -s contract.sol

# Analyze with assertion checking
python oyente/oyente.py -a -s contract.sol

# Analyze EVM bytecode
python oyente/oyente.py -s bytecode_file -b

# Analyze remote contract
python oyente/oyente.py -ru https://example.com/contract.sol

# Get help
python oyente/oyente.py --help
```

### Development Workflow

```bash
# Format, lint, type-check, and test (run before commits)
make all

# Individual commands
make format      # Format with Black
make lint        # Check with Ruff
make type-check  # Verify with mypy
make test        # Run all tests
make test-cov    # Run tests with coverage
```

## 🧪 Testing

The project includes comprehensive testing infrastructure:

```bash
# Run all tests using Makefile (preferred)
make test

# Run specific test types
make test-unit           # Unit tests only (tests/unit/)
make test-integration    # Integration tests only (tests/integration/)
make test-performance    # Performance tests only (tests/performance/)
make test-property       # Property-based tests only (tests/property/)

# Run specific test file
make test TEST=tests/unit/test_analysis.py

# Run tests with coverage reporting
make test-cov                    # All tests with coverage
make test-unit-cov               # Unit tests with coverage
make test-integration-cov        # Integration tests with coverage

# Run specific test file with coverage
make test-cov TEST=tests/unit/test_analysis.py

# Run legacy EVM tests (JSON-based)
make test-legacy

# Direct pytest commands (alternative)
python -m pytest tests/ -v           # All tests
python -m pytest tests/unit/         # Unit tests only
python -m pytest tests/integration/  # Integration tests only
python -m pytest -m "not slow"       # Skip slow tests
python -m pytest -m integration      # Integration tests by marker
python -m pytest -m unit             # Unit tests by marker
```

### Test Structure

```
tests/
├── unit/           # Fast, isolated unit tests (make test-unit)
├── integration/    # Component interaction tests (make test-integration)
├── property/       # Hypothesis property-based tests (make test-property)
├── performance/    # Benchmark tests (make test-performance)
├── fixtures/       # Test data and utilities
└── mocks/          # Mock objects for Z3, filesystem, etc.
```

## 📊 Architecture Overview

### Core Components

- **`oyente/oyente.py`**: Main CLI entry point and configuration
- **`oyente/input_helper.py`**: Input handling for Solidity/bytecode using crytic-compile
- **`oyente/symExec.py`**: Symbolic execution engine with Z3 constraint solving
- **`oyente/vulnerability.py`**: Vulnerability detection classes (27+ tests ✅)
- **`oyente/analysis.py`**: Analysis state management and vulnerability reporting

### Analysis Flow

1. **Input Processing**: Compile Solidity or parse bytecode
2. **CFG Construction**: Build control flow graph from EVM opcodes
3. **Symbolic Execution**: Explore paths with constraint solving
4. **Vulnerability Detection**: Apply security analysis patterns
5. **Report Generation**: Output findings with source mapping

### Supported Vulnerabilities

- **Reentrancy**: External call state manipulation
- **Integer Overflow/Underflow**: Arithmetic boundary violations
- **Timestamp Dependence**: Block timestamp manipulation
- **Callstack Attack**: Call depth limitations
- **Concurrency Issues**: Transaction ordering dependencies
- **Assertion Failures**: Solidity assert statement violations

## 🛠️ Development

### Project Status

**✅ Completed (Phase 1)**:
- **PEP 621 compliant packaging** with Poetry integration
- **Comprehensive pyproject.toml configuration** for all tools
- **Organized dependency groups** (dev, test, lint)
- **Comprehensive test infrastructure** (27+ unit tests)
- **Security-first code quality tooling** (Black, Ruff, mypy)
- **Type hints for `vulnerability.py` module** (100% coverage)

**🔄 In Progress**:
- Type hints for core modules (`oyente.py`, `input_helper.py`)
- Linting error resolution (659 remaining)
- Expanded test coverage for `symExec.py`

**📋 Roadmap**:
- Architectural refactoring of monolithic `symExec.py`
- Plugin architecture for vulnerability detectors
- Performance optimizations
- CI/CD pipeline implementation

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
   make setup
   poetry shell
   ```

2. **Make Changes**: Follow existing code patterns and conventions

3. **Run Quality Checks**:
   ```bash
   make all  # Must pass before committing
   ```

4. **Add Tests**: All new functionality requires tests

5. **Documentation**: Update docstrings and README as needed

## 📈 Benchmarks & Testing

### Legacy EVM Tests

JSON-based tests from Ethereum VM test suite:

```bash
python oyente/run_tests.py
```

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

## 📚 Resources

- **Original Paper**: [Oyente: Making Smart Contracts Safer](https://www.comp.nus.edu.sg/~prateeks/papers/Oyente.pdf)

## 🤝 Contributing

We welcome contributions! Please:

1. **Open an Issue**: Report bugs or suggest features on our [issue tracker](https://github.com/smartbugs/oyente_plus/issues)
2. **Submit PRs**: Feel free to send us a PR for changes you want to see!
3. **Follow Standards**: Ensure all quality checks pass with `make all`

### Development Setup

```bash
git clone https://github.com/smartbugs/oyente_plus.git
cd oyente_plus
make setup
poetry shell
make all  # Verify everything works
```

[license-badge]: https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=flat-square
[license-badge-url]: ./LICENSE
