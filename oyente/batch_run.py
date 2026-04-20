import glob
import json
import os
import subprocess
import sys

from tqdm import tqdm

contract_dir = "contract_data"

cfiles = glob.glob(contract_dir + "/contract1.json")

cjson = {}

print("Loading contracts...")

for cfile in tqdm(cfiles):
    with open(cfile) as f:
        cjson.update(json.loads(f.read()))

results = {}
missed = []

print("Running analysis...")

contracts = list(cjson.keys())

if os.path.isfile("results.json"):
    with open("results.json") as f:
        old_res = json.loads(f.read())
    old_res = list(old_res.keys())
    contracts = [c for c in contracts if c not in old_res]

cores = 0
job = 0

if len(sys.argv) >= 3:
    cores = int(sys.argv[1])
    job = int(sys.argv[2])
    contracts = contracts[(len(contracts) // cores) * job : (len(contracts) // cores) * (job + 1)]
    print(f"Job {job}: Running on {len(contracts)} contracts...")

for c in tqdm(contracts):
    with open("tmp.evm", "w") as of:
        of.write(cjson[c][1][2:])
    subprocess.run([sys.executable, "oyente.py", "-ll", "30", "-s", "tmp.evm", "-j", "-b"], check=False)
    try:
        with open("tmp.evm.json") as f:
            results[c] = json.loads(f.read())
    except (FileNotFoundError, json.JSONDecodeError):
        missed.append(c)
    with open("results.json", "w") as of:
        of.write(json.dumps(results, indent=1))
    with open("missed.json", "w") as of:
        of.write(json.dumps(missed, indent=1))
    # urllib.request.urlopen('https://dweet.io/dweet/for/oyente-%d-%d?completed=%d&missed=%d&remaining=%d' % (job,cores,len(results),len(missed),len(contracts)-len(results)-len(missed)))

print("Completed.")
