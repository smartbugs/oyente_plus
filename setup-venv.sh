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
pip install z3-solver
pip install crytic_compile
