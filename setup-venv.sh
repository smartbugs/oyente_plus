#!/bin/bash
# tested for python 3.10
python3 -m venv venv
source venv/bin/activate

# avoid spurious errors/warnings; the next two lines could be omitted
pip install --upgrade pip
pip install wheel

# install the packages needed by Oyente
pip install six
pip install z3
pip install requests
pip install z3-solver==4.5.1
pip install crytic_compile==0.3.1
pip install web3
pip install evmdasm
pip install pyevmdasm
