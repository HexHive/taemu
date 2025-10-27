import json
import sys
import os

BASE = os.path.dirname(__file__)
PROJ = os.path.join(BASE, "..")

out = {}
tees = ["mitee", "teegris", "t6", "beanpod"]
for tee in tees:
    out[tee] = {}
    bb_dir = os.path.join(PROJ, tee, "tas", "bbs")
    for json_f in os.listdir(bb_dir):
        print(bb_dir, json_f)
        try:
            a = json.load(open(os.path.join(bb_dir, json_f)))
        except:
            continue
        for f, data in a.items():
            for node in data["nodes"]:
                for call in node["calls"]:
                    if call["api_type"] == "tee":
                        fname = call["func"]
                        if fname in out[tee]:
                            out[tee][fname] += 1
                        else:
                            out[tee][fname] = 1
print(out)

for tee, funcs in out.items():
    print(f"\n=== {tee.upper()} (top 10 calls) ===")
    top10 = sorted(funcs.items(), key=lambda x: x[1], reverse=True)[:10]
    for name, count in top10:
        print(f"{name:<40} {count}")
