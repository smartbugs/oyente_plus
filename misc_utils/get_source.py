import json
import os
import re
import subprocess

from tqdm import tqdm


def get_contract_code(cadd: str) -> tuple[list[str], list[str]]:
    sourcepattern = r"style='max-height: 250px; margin-top: 5px;'>([\s\S]+?)<\/pre>"
    namepattern = r"<td>Contract Name:[\n.]<\/td>[\n.]<td>[.\n]([\s\S]+?)[\n.]<\/td>"
    command = f"wget -S -O - 'https://etherscan.io/address/{cadd}#code'"
    with open(os.devnull, "wb") as devnull:
        wget = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=devnull)  # noqa: S602
        if wget.stdout:
            outp = wget.stdout.read()
            return (re.findall(namepattern, outp.decode()), re.findall(sourcepattern, outp.decode()))
        return ([], [])


savedcontracts: list[tuple[str, str, float]] = []


def save_callstack_source(dirname: str) -> None:
    if not dirname.endswith("/"):
        dirname += "/"
    print("Loading callstack file...")
    with open("callstack_stats.json") as f:
        cstkfile = json.load(f)
    with open("cterror_balances.json") as f:
        cstbfile = json.load(f)
    for contract in tqdm(cstkfile):
        name, source = get_contract_code(contract)
        if len(source) <= 0:
            continue
        source_text = source[0]
        fname = name[0] if len(name) > 0 else contract
        # print("Saved contract %s to %s.sol" % (contract, fname))
        if os.path.isfile(dirname + fname + ".sol"):
            i = 0
            while os.path.isfile(dirname + fname + str(i) + ".sol"):
                i += 1
            fname += str(i)
        fname += ".sol"
        balance = cstbfile[cstkfile.index(contract)] / 1000000000000000000.0
        savedcontracts.append((contract, fname, balance))
        with open(dirname + fname, "w") as of:
            of.write(f"// {contract}\n// {balance}\n")
            of.write(source_text)
            of.flush()
            of.close()


if __name__ == "__main__":
    save_callstack_source("source")
