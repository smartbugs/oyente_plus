import json
import os
import re
from typing import Any

from tqdm import tqdm


def get_transactions(fname: str) -> list[dict[str, Any]]:
    pattern = r"(>(0x[\da-f]+)<|block\/(\d+)|<td>(\d.+?)</td>)"
    with open(fname) as f:
        res = re.findall(pattern, f.read(), re.IGNORECASE)
    txs: list[dict[str, Any]] = []
    curtx: dict[str, Any] = {}

    for match in res:
        if match[2] != "":
            if len(txs) > 0:
                txs[-1]["transactions"] = txs[-1]["transactions"][:-1]
            curtx = {}
            curtx["transactions"] = []
            curtx["transactions"].append({})
            txs.append(curtx)
        if match[1] != "":
            if "txid" not in curtx:
                curtx["txid"] = match[1]
            else:
                if "from" not in curtx["transactions"][-1]:
                    curtx["transactions"][-1]["from"] = match[1]
                elif "to" not in curtx["transactions"][-1]:
                    curtx["transactions"][-1]["to"] = match[1]
        if match[3] != "":
            curtx["transactions"][-1]["worth"] = match[3]
            curtx["transactions"].append({})
    return txs


def load_txdir(path: str) -> list[dict[str, Any]]:
    files = os.listdir(path)
    if path[-1] != "/":
        path += "/"
    txs: list[dict[str, Any]] = []
    for f in tqdm(files):
        if f.endswith(".html"):
            txs += get_transactions(path + f)
    return txs


def pprint(fn: str) -> None:
    with open(fn) as f:
        inj = json.loads(f.read())
    with open(fn, "w") as outj:
        outj.write(json.dumps(inj, indent=1))


txs_dir = "../transaction-scraper/transactions"
print("Loading transactions...")
txs = load_txdir(txs_dir)
print("Saving...")
with open("transactions.json", "w") as tfile:
    tfile.write(json.dumps(txs, indent=1))
    tfile.close()
print("Done.")
