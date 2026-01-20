import json
import os
import sys



if len(sys.argv) < 2:
    print("give path to sus_inputs_replay")
    exit(0)

dfs = 0
for f in os.listdir(sys.argv[1]):
    if not f.endswith(".meta"): continue
    meta_data = json.load(open(os.path.join(sys.argv[1], f)))
    for entry in f["records"]:
        if entry["is_second_fetch"]: dfs += 1

print(f'{sys.argv[1]} nr dfs: {dfs}')
