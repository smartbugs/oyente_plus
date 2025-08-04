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
- **Comprehensive Testing**: 406+ test functions (342 unit + 64 integration) with property-based testing
- **Code Quality**: Enforced with Black, Ruff, mypy, and pytest
- **Latest EVM Support**: Compatible with recent opcodes (PUSH0, TLOAD, TSTORE)

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (excluding 3.12.0) - Modern type hints and features
- **[Poetry](https://python-poetry.org/)** - PEP 621 compliant dependency management  
- **[Solidity compiler (solc)](https://docs.soliditylang.org/en/latest/installing-solidity.html)** - Contract compilation
- **[Go Ethereum (geth)](https://geth.ethereum.org/downloads/)** - EVM execution engine
- **[Docker](https://docs.docker.com/get-docker/)** (optional) - For containerized deployment

### Installation

#### Option 1: Using Make (Recommended)

```bash
# Clone the repository
git clone https://github.com/smartbugs/oyente_plus.git
cd oyente_plus

# Setup development environment with all dependencies
make setup

# Virtual environment is automatically activated by the setup script
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

For users who prefer containerized deployment, ensure you have [Docker installed](https://docs.docker.com/get-docker/).

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

**Status**: 406+ test functions (342 unit + 64 integration) across comprehensive test infrastructure (99% pass rate)

```bash
# Quick commands
make test          # Run all tests
make test-unit     # Unit tests only
make test-cov      # Tests with coverage
make all          # Format, lint, type-check, test
```

**📋 For detailed testing guide**: See `docs/testing.md`

## 📊 Architecture Overview

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
- **Comprehensive test infrastructure** (406+ test functions, 99% pass rate)
- **Security-first code quality tooling** (Black, Ruff, mypy)
- **Complete test coverage** for all core modules: `vulnerability.py`, `analysis.py`, `input_helper.py`, `ast_helper.py`
- **Initial test coverage** for `symExec.py` (25+ tests) with ongoing expansion
- **Full test coverage** for supporting modules: `vargenerator.py`, `basicblock.py`, `utils.py`, `ast_walker.py`
- **Type hints and docstrings** for core modules (`vargenerator.py`, `oyente.py`, `opcodes.py`, `global_params.py`, `basicblock.py`)
- **Robust mocking infrastructure** for Z3, filesystem, and external dependencies

**🔄 In Progress (Phase 2)**:
- **Critical Code Quality** (P0): Fix remaining 3555+ mypy errors across main codebase
- **Type hints for remaining modules** (`input_helper.py`, `analysis.py`, `symExec.py`)
- **Linting error resolution** (600+ Ruff errors, focus on security S-codes)
- **Type hints added** to all core modules with comprehensive docstrings

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
   source venv/bin/activate
   ```

2. **Make Changes**: Follow existing code patterns and conventions

3. **Run Quality Checks**:
   ```bash
   make all  # Must pass before committing
   ```

4. **Add Tests**: All new functionality requires tests

5. **Documentation**: Update docstrings and README as needed

## 📈 Benchmarks & Testing

### Modern Test Infrastructure

Comprehensive testing with pytest:

```bash
make test           # Run all tests (406+ functions)
make test-unit      # Unit tests only (342 functions)
make test-integration  # Integration tests only (64 functions)
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
source venv/bin/activate
make all  # Verify everything works
```

[license-badge]: https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=flat-square
[license-badge-url]: ./LICENSE
