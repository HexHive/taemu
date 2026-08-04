import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_json(path: str):
    with open(path, "r") as f:
        data = json.load(f)
    return data


def scan_dir(path: str):
    results = []
    for root, dirs, files in os.walk(path):
        if "suspicious_inputs" not in root:
            continue

        for file in files:
            if file.endswith(".meta"):
                results.append(os.path.join(root, file))
    return results

def mt_parse_jsons(paths: list[str]):
    results = []
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
        futures = [ex.submit(parse_json, path) for path in paths]
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
    return results

if __name__ == "__main__":
    results = scan_dir("/root/TA_GP_emulator")
    print(len(results))
    exit(0)
    mt_parse_jsons(results)

