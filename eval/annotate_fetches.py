import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
import os
import json


def get_all_suspicious_inputs(path="/root/TA_GP_emulator"):
    suspicious_inputs = []
    for root, dirs, files in os.walk(path):
        for file in files:
            path = os.path.join(root, file)
            if "suspicious_inputs_replay/" in path:
                suspicious_inputs.append(path)
    return suspicious_inputs

def group_pair(suspicious_input_paths):
    grouped_inputs = {}
    for path in suspicious_input_paths:
        base_dir = os.path.dirname(path).replace("suspicious_inputs_replay", "")
        if base_dir not in grouped_inputs:
            grouped_inputs[base_dir] = []
        grouped_inputs[base_dir].append(path)
    return grouped_inputs

def validate(args):
    if os.path.exists("/.dockerenv"):
        print("[-] ERROR! Please run annotate_fetches.py outside of the emulator container")
        exit(3)

class Accesses:
    def __init__(self):
        self.ranges = []
        pass
    def visit(self, start, end):
        for ex_start, ex_end in self.ranges:
            if start < ex_end and ex_start < end:
                self.ranges.append((start,end))
                return True
        self.ranges.append((start,end))
        return False

def annotate_dfs(meta_data):
    accesses = Accesses()
    fetches = 0
    for i, record in enumerate(meta_data["records"]):
        addr = record["addr"]
        size = 1 if record["size"] is None else record["size"]
        end = addr + size
        if accesses.visit(addr, end):
            meta_data["records"][i]["is_second_fetch"] = True
            fetches += 1
        else:
            meta_data["records"][i]["is_second_fetch"] = False
    return meta_data, fetches

def handle_in(in_path):
    sus_path = os.path.join(in_path, "suspicious_inputs_replay")
    if not os.path.exists(sus_path):
        return 0
    all_dfs = 0
    for meta in [f for f in os.listdir(sus_path) if f.endswith(".meta")]:
        meta_path = os.path.join(sus_path, meta)
        all_dfs += handle_meta(meta_path)
    return all_dfs

def handle_meta(meta_path):
    try:
        meta_data = json.load(open(meta_path))
        meta_data, fetches = annotate_dfs(meta_data)
        open(meta_path, "w+").write(json.dumps(meta_data, indent=4))
    except Exception as e:
        print("=======================[+] ERROR =======================")
        print(meta_path)
        print(e)
        print("=======================[+] ERROR=======================")
        with open("annotate_fetches_error.txt", "a") as f:
            f.write(meta_path + "\n")
            f.write(str(e) + "\n")
            f.write("=======================[+] ERROR=======================\n")
        return 0
    return fetches

def main(in_paths):
    results = []
    with ProcessPoolExecutor() as pool:
        futures = [pool.submit(handle_in, x) for x in in_paths]
        for f in tqdm(as_completed(futures), total=len(futures)):
            results.append(f.result())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, default="/root/TA_GP_emulator")
    parser.add_argument("--tee", type=str, default="all")
    parser.add_argument("--single", type=str, required=False)
    
    args = parser.parse_args()
    
    
    if "eval" in os.getcwd() or "TA_GP_emulator" not in os.getcwd():
        print(f"[-] Please run annotate_fetches.py at /{os.getlogin()}/TA_GP_emulator")
        exit(1)
    
    print(
        "[+] Processing path: {} annotaing double fetches".format(
            args.path,
        )
    )
    validate(args)
    if args.single:
        print(handle_in(args.single))
        exit(0)

    suspicious_input_paths = get_all_suspicious_inputs(args.path)
    grouped_inputs = group_pair(suspicious_input_paths)
    if args.tee != "all":
        grouped_inputs = {k: v for k, v in grouped_inputs.items() if args.tee in k}
    main(grouped_inputs.keys())
