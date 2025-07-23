Oyente+
=======

An Analysis Tool for Smart Contracts

[![License: GPL v3][license-badge]][license-badge-url]

*This repository is currently maintained by Thomas Fenninger ([@zariliv](https://github.com/zariliv)). If you encounter any bugs or usage issues, please feel free to create an issue on [our issue tracker](https://github.com/smartbugs/oyente_plus/issues).*

## Quick Start

A container with required dependencies configured can be found [here](https://hub.docker.com/r/smartbugs/oyente_plus/).

To open the container, install docker and run:

```shell
docker pull smartbugs/oyente_plus && docker run -i -t smartbugs/oyente_plus
```

To evaluate the greeter contract inside the container, run:

```shell
cd /oyente/oyente && python oyente.py -s greeter.sol
```

and you are done!

## Custom Docker image build

```shell
docker build -t oyente_plus .
docker run -it -e "OYENTE=/oyente/oyente" oyente_plus:latest
```

## Installation

Run the setup-venv.sh shell script to create a new python virtualenv and install all dependencies.

```shell
./setup-venv.sh
```

### Install the following dependencies

#### solc

```shell
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```

#### evm from [go-ethereum](https://github.com/ethereum/go-ethereum)

1. https://geth.ethereum.org/downloads/ or
2. By from PPA if your using Ubuntu

```shell
sudo apt-get install software-properties-common
sudo add-apt-repository -y ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install ethereum
```

### Evaluating Ethereum Contracts

```shell
#evaluate a local solidity contract
python oyente.py -s <contract filename>

#evaluate a local solidity with option -a to verify assertions in the contract
python oyente.py -a -s <contract filename>

#evaluate a local evm contract
python oyente.py -s <contract filename> -b

#evaluate a remote contract
python oyente.py -ru https://gist.githubusercontent.com/loiluu/d0eb34d473e421df12b38c12a7423a61/raw/2415b3fb782f5d286777e0bcebc57812ce3786da/puzzle.sol

```

And that's it! Run ```python oyente.py --help``` for a list of options.

## Paper

The accompanying paper explaining the bugs detected by the tool can be found [here](https://www.comp.nus.edu.sg/~prateeks/papers/Oyente.pdf).

## Miscellaneous Utilities

A collection of the utilities that were developed for the paper are in `misc_utils`. Use them at your own risk - they have mostly been disposable.

1. `generate-graphs.py` - Contains a number of functions to get statistics from contracts.
2. `get_source.py` - The *get_contract_code* function can be used to retrieve contract source from [EtherScan](https://etherscan.io)
3. `transaction_scrape.py` - Contains functions to retrieve up-to-date transaction information for a particular contract.

## Benchmarks

Note: This is an improved version of the tool used for the paper. Benchmarks are not for direct comparison.

To run the benchmarks, it is best to use the docker container as it includes the blockchain snapshot necessary.
In the container, run `batch_run.py` after activating the virtualenv. Results are in `results.json` once the benchmark completes.

The benchmarks take a long time and a *lot* of RAM in any but the largest of clusters, beware.

Some analytics regarding the number of contracts tested, number of contracts analysed etc. is collected when running this benchmark.

## Contributing

Find a bug, a way to improve the documentation or have a feature request? Open an [issue](https://github.com/smartbugs/oyente_plus/issues/new).

Or even better, send us a PR :)

### Before you send PRs
- Follow the [instructions](https://github.com/smartbugs/oyente_plus#full-install) to get a locally working version of oyente+
- Make your awesome change
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)

[license-badge]: https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=flat-square
[license-badge-url]: ./LICENSE
