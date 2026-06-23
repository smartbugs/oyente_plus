# Oyente+ &ndash; an Analysis Tool for Smart Contracts

[![License: GPL v3][license-badge]][license-badge-url]
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![Code style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)
[![CI/CD Pipeline](https://github.com/smartbugs/oyente_plus/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/smartbugs/oyente_plus/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/smartbugs/oyente_plus/branch/main/graph/badge.svg)](https://codecov.io/gh/smartbugs/oyente_plus)

## History

**Oyente+** is a modernized version of the [original Oyente](https://github.com/enzymefinance/oyente) symbolic execution tool for Ethereum smart contracts. Oyente and Oyente+ are designed to detect smart-contract weaknesses like reentrancy, integer overflow, and timestamp dependence.
As one of the earliest tools in the field, Oyente has served as a foundation for extensions and as a reference point for evaluating new approaches. Over time, however, it has become increasingly difficult to use: it cannot analyze newer contracts that rely on EVM instructions introduced after its initial release (for example, the shift opcodes or PUSH0), and it depends on Python 2 and outdated libraries, which complicates installation.
Oyente+ preserves Oyente's analysis capabilities while providing full support for the current EVM instruction set. The codebase has been ported to Python 3 and updated to follow contemporary software-engineering practices

## Installation

### Dependencies

- **Python 3.8+** (excluding 3.12.0, but 3.12.1+ is fine)
- **[Poetry](https://python-poetry.org/)** - PEP 621 compliant dependency management
- **[Solidity compiler (solc)](https://docs.soliditylang.org/en/latest/installing-solidity.html)** - Contract compilation
- **[Docker](https://docs.docker.com/get-docker/)** (optional) - For containerized deployment

### Installation

```bash
# Start by cloning the repository.
git clone https://github.com/smartbugs/oyente_plus.git
cd oyente_plus
```

#### Option 1: setup script

```bash
./scripts/setup-venv.sh  # setup virtual env with all dependencies
source venv/bin/activate # activate virtual env
```

#### Option 2: make (poetry required)

```bash
make setup
```

#### Option 3: manual setup (poetry required)

```bash
poetry install --with dev  # install with development tooling
# or alternatively
poetry install --only main # install for production only
```

#### Option 4: docker

```bash
# make sure you have Docker installed
docker pull smartbugs/oyente_plus
docker run -it smartbugs/oyente_plus
```

### Dependency: the Solidity compiler

```bash
# Use solc-select for version management (recommended)
solc-select install latest
solc-select use latest

# Ubuntu/Debian
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```

## Usage

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


## Resources

- **Original Paper**: [Oyente: Making Smart Contracts Safer](https://www.comp.nus.edu.sg/~prateeks/papers/Oyente.pdf)

## Contributing

We welcome contributions! Please:

1. **Open an Issue**: Report bugs or suggest features on our [issue tracker](https://github.com/smartbugs/oyente_plus/issues)
2. **Submit PRs**: Feel free to send us a PR for changes you want to see!
3. **Follow Standards**: Ensure all quality checks pass with `make all`

See the [development guide](https://github.com/smartbugs/oyente_plus/blob/master/development.md) for more information on the architecture of Oyente+ and the development environment.


[license-badge]: https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=flat-square
[license-badge-url]: ./LICENSE
