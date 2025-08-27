# Sample Contracts

Folder `0.4.x` contains 10 'real-world' contracts from Ethereum's main chain. They are a subset of the [SmartBugs Curated Dataset](https://github.com/smartbugs/smartbugs-curated). The bytecode is the one deployed on the blockchain. For details about the compiler settings for generating it from the source code, see [Etherscan](https://etherscan.com).

The folders `0.5.17`, `0.6.12`, `0.7.6`, and `0.8.24` contain the same contracts but adapted to the respective Solidity version. The bytecodes were obtained by compiling the source code without additional flags.

## Running Oyente+ on all samples

### Using the shell

For `bash` and similar shells, the following commands run Oyente on all
sample contracts and store the output in a folder `results`.

```bash
# activate virtual environment
. ../venv/bin/activate

# create result folders
for d in *; do
    if [ -d "$d" ]; then
        mkdir -p "../results/$d"
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
    ../oyente/oyente.py -glt 300 -s "$c" > "../results/$c.log" 2>&1
done

# analyze contracts given by runtime bytecode 
for c in */*.rt.hex; do
    echo "$c"
    ../oyente/oyente.py -glt 300 -b -s "$c" > "../results/$c.log" 2>&1
done
```

### Using SmartBugs

[SmartBugs](https://github.com/smartbugs/smartbugs) is a framework for running several tools on many contracts simultaneously. It comes with a selection of tools, including Oyente+.
Use a command like
```bash
smartbugs -t oyente+ -f **/* --results 'results/${TOOL}/${RELDIR}/${FILENAME}' --timeout 300 --processes 4 --mem-limit 2g
reparse results
results2csv results > results.csv
```
