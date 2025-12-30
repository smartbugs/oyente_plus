# Oyente+

An Analysis Tool for Smart Contracts

[![License: GPL v3][license-badge]][license-badge-url]
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![Code style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)
[![CI/CD Pipeline](https://github.com/smartbugs/oyente_plus/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/smartbugs/oyente_plus/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/smartbugs/oyente_plus/branch/main/graph/badge.svg)](https://codecov.io/gh/smartbugs/oyente_plus)

*This repository is currently maintained by Thomas Fenninger ([@zariliv](https://github.com/zariliv)). If you encounter any bugs or usage issues, please feel free to create an issue on [our issue tracker](https://github.com/smartbugs/oyente_plus/issues).*

**Oyente+** is a modernized version of the [original Oyente](https://github.com/enzymefinance/oyente) symbolic execution tool for Ethereum smart contracts. Oyente and Oyente+ are designed to detect smart-contract weaknesses like reentrancy, integer overflow, and timestamp dependence.

## ✨ Features

- **Detection of smart contract weaknesses:** reentrancy issues, integer over-/underflow, timestamp dependence, transaction order dependence, assertion failures
- **Symbolic Execution**: Deep analysis using the Z3 constraint solver
- **Multi-format Support**: Analyze Solidity source code, EVM bytecode, or remote on-chain contracts

As one of the earliest tools in the field, Oyente has served as a foundation for extensions and as a reference point for evaluating new approaches. Over time, however, it has become increasingly difficult to use: it cannot analyze newer contracts that rely on EVM instructions introduced after its initial release (for example, the shift opcodes or PUSH0), and it depends on Python 2 and outdated libraries, which complicates installation.

Oyente+ preserves Oyente's analysis capabilities while providing full support for the complete EVM instruction set. The codebase has been ported to Python 3 and updated to follow contemporary software-engineering practices. In particular, Oyente+ offers:

- **Latest EVM Support**: Compatible with recent opcodes (e.g., PUSH0, TLOAD, TSTORE)
- **Modern Python**: Implemented in Python 3.8+ with comprehensive type hints
- **Comprehensive Testing**: 513 test functions with a 100% pass rate, including property-based tests
- **High Code Quality**: Enforced through Black, Ruff, mypy, and pytest
- **Strong Type Safety**: Zero mypy errors across 15 of 17 modules

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (excluding 3.12.0) - Modern type hints and features
- **[Poetry](https://python-poetry.org/)** - PEP 621 compliant dependency management
- **[Solidity compiler (solc)](https://docs.soliditylang.org/en/latest/installing-solidity.html)** - Contract compilation
- **[Docker](https://docs.docker.com/get-docker/)** (optional) - For containerized deployment

Note: Python 3.12.0 is excluded due to upstream library incompatibilities in that specific initial release; patch releases (3.12.1+) resolve these issues and are allowed.

### Installation

```bash
# Clone the repository
git clone https://github.com/smartbugs/oyente_plus.git
cd oyente_plus
```

#### Option 1: Using Setup Script

```bash
# Setup development environment with virtual environment and all dependencies
./scripts/setup-venv.sh

# Activate the environment
source venv/bin/activate
```

#### Option 2: Using Make (Poetry Required)

```bash
# If you already have Poetry installed
make setup

# Virtual environment detection is automatic
```

#### Option 3: Manual Setup (Poetry Required)

```bash
# Install all dependencies (development, testing, linting)
poetry install --with dev

# Production installation only
poetry install --only main
```

#### Option 4: Docker

For users who prefer containerized deployment, ensure you have [Docker installed](https://docs.docker.com/get-docker/).

```bash
docker pull smartbugs/oyente_plus
docker run -it smartbugs/oyente_plus
```

### System Dependencies

#### Solidity Compiler

```bash
# Use solc-select for version management (recommended)
solc-select install latest
solc-select use latest

# Ubuntu/Debian
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```


## 🔧 Usage

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

See the [development guide](https://github.com/smartbugs/oyente_plus/blob/master/development.md) for more information on the architecture of Oyente+ and the development environment.


[license-badge]: https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=flat-square
[license-badge-url]: ./LICENSE
