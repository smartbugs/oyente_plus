#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Change to the samples directory (samples by default)
SAMPLES_DIR="${1:-$PROJECT_ROOT/samples}"
cd "$SAMPLES_DIR" || exit 1

# activate virtual environment
source "$PROJECT_ROOT/venv/bin/activate"

# create result folders
for d in *; do
    if [ -d "$d" ]; then
        mkdir -p "$PROJECT_ROOT/results/$d"
    fi
done

# analyze contracts given by Solidity sourcecode
solc-select install 0.4.25
solc-select install 0.5.17
solc-select install 0.6.12
solc-select install 0.7.6
solc-select install 0.8.24
for c in */*.sol; do
    echo "$c"
    s=${c%%/*}
    solc-select use "${s/x/25}"
    python "$PROJECT_ROOT/oyente/oyente.py" -glt 300 -s "$c" > "$PROJECT_ROOT/results/$c.log" 2>&1
done

# analyze contracts given by runtime bytecode
for c in */*.rt.hex; do
    echo "$c"
    python "$PROJECT_ROOT/oyente/oyente.py" -glt 300 -b -s "$c" > "$PROJECT_ROOT/results/$c.log" 2>&1
done
