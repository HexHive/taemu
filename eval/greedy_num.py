import json
import os

tees = ["all", "teegris", "mitee", "t6", "beanpod"]

for tee in tees:
    data = json.load(open(f"bbs_out/{tee}_noorder.json"))
    m = max(data)
    for i, d in enumerate(data):
        if d >= 0.9 * m:
            print(f'{tee}: 0.8 bbs: {i+1}')
            break
