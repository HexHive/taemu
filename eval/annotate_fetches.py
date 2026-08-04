import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
import os
import json

import taemu_env


# Which recording directories to annotate. "suspicious_inputs_replay" holds the
# deduplicated seeds that Fetch-Anchored Fuzzing works on; "suspicious_inputs"
# holds every input the recorder flagged during Exploration and is needed to
# count the *raw* number of overlapped fetches (Table I, column 4).
DIRS = {
    "replay": ["suspicious_inputs_replay/"],
    "raw": ["suspicious_inputs/"],
    "both": ["suspicious_inputs_replay/", "suspicious_inputs/"],
}


def get_all_suspicious_inputs(path=None, dirs="replay"):
    path = path or taemu_env.repo_root()
    wanted = DIRS[dirs]
    suspicious_inputs = []
    for root, _, files in os.walk(path):
        for file in files:
            p = os.path.join(root, file)
            if any(w in p for w in wanted):
                suspicious_inputs.append(p)
    return suspicious_inputs

def group_pair(suspicious_input_paths):
    grouped_inputs = {}
    for path in suspicious_input_paths:
        base_dir = os.path.dirname(path)
        base_dir = base_dir.replace("suspicious_inputs_replay", "").replace(
            "suspicious_inputs", "")
        if base_dir not in grouped_inputs:
            grouped_inputs[base_dir] = []
        grouped_inputs[base_dir].append(path)
    return grouped_inputs

def validate(args):
    # annotate_fetches only rewrites .meta files, no docker needed
    return

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

def handle_in(in_path, dirs="replay"):
    all_dfs = 0
    for sub in DIRS[dirs]:
        sus_path = os.path.join(in_path, sub.rstrip("/"))
        if not os.path.exists(sus_path):
            continue
        for meta in [f for f in os.listdir(sus_path) if f.endswith(".meta")]:
            all_dfs += handle_meta(os.path.join(sus_path, meta))
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

def main(in_paths, dirs="replay"):
    results = []
    with ProcessPoolExecutor() as pool:
        futures = [pool.submit(handle_in, x, dirs) for x in in_paths]
        for f in tqdm(as_completed(futures), total=len(futures)):
            results.append(f.result())
    print(f"[+] annotated overlapped fetches: {sum(results)}")
    return sum(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, default=taemu_env.repo_root())
    parser.add_argument("--tee", type=str, default="all")
    parser.add_argument("--single", type=str, required=False)
    parser.add_argument(
        "--dirs",
        choices=sorted(DIRS.keys()),
        default="replay",
        help="which recording directories to annotate (default: replay)",
    )
    
    args = parser.parse_args()
    
    
    print(
        "[+] Processing path: {} annotaing double fetches".format(
            args.path,
        )
    )
    validate(args)
    if args.single:
        print(handle_in(args.single, args.dirs))
        exit(0)

    suspicious_input_paths = get_all_suspicious_inputs(args.path, args.dirs)
    grouped_inputs = group_pair(suspicious_input_paths)
    if args.tee != "all":
        grouped_inputs = {k: v for k, v in grouped_inputs.items() if args.tee in k}
    main(grouped_inputs.keys(), args.dirs)
