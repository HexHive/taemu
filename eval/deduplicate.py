# Backup side-road deduplication

import json
import os

import argparse
import asyncio
from typing import Any, List
import re
import subprocess
import signal
import hashlib
import struct
import time
import tqdm
import aiofiles

MIN_DRCOV_FILE_SIZE = 20
DRCOV_VERSION = 2

DRCOV_HEADER_RE = r"DRCOV VERSION: (?P<version>\d+)\n"
MODULE_HEADER_V2_RE = (
    r"Module Table: version (?P<version>\d+), count (?P<mod_num>\d+)\n"
)
BB_HEADER_RE = r"BB Table: (?P<bbcount>\d+) bbs\n"


class BB:
    def __init__(self, ta, start, size, mod_id):
        self.ta = ta
        self.start = start
        self.size = size
        self.mod_id = mod_id

    def __eq__(self, other):
        return (
            self.start == other.start
            and self.size == other.size
            and self.ta == other.ta
            and self.mod_id == other.mod_id
        )

    def __str__(self):
        return f"BB(ta: {self.ta}, start: {self.start}, size: {self.size}, mod_id: {self.mod_id})"

    def __hash__(self):
        return hash((self.start, self.size, self.ta, self.mod_id))

    def __lt__(self, other):
        return self.start < other.start


def parse_drcov(tee, ta, path):
    bbs_out = []
    raw = open(path, "rb").read()
    ta_base = raw.split(b"timestamp, path\n")[-1]
    for l in ta_base.split(b"\n"):
        if b"emulator/rootfs" in l and b".ta" in l:
            base = l.split(b",")[1]
            base = int(base.decode())
            ta_id = int(l.split(b",")[0])
    nr_bbs = raw.split(b"BB Table: ")[-1]
    nr_bbs = int(nr_bbs.split(b"bbs\n")[0].decode())
    bbs = raw.split(b"bbs\n")[-1]
    for _ in range(nr_bbs):
        start = int.from_bytes(bbs[0:4], "little")
        size = int.from_bytes(bbs[4:6], "little")
        mod_id = int.from_bytes(bbs[6:8], "little")
        if mod_id == ta_id:
            if tee == "beanpod" or tee == "t6":
                start = base + start
            bbs_out.append(BB(ta, start, size, mod_id))
        bbs = bbs[8:]
    return bbs_out


def get_all_suspicious_inputs(path="/root/TA_GP_emulator"):
    suspicious_inputs = []
    for root, dirs, files in os.walk(path):
        for file in files:
            path = os.path.join(root, file)
            if "suspicious_inputs" in path:
                suspicious_inputs.append(path)
    return suspicious_inputs


def del_duplicate(meta_path):
    if meta_path.endswith(".meta"):
        if os.path.exists(meta_path):
            os.remove(meta_path)
        if os.path.exists(meta_path.replace(".meta", "")):
            os.remove(meta_path.replace(".meta", ""))
    else:
        input_path = meta_path
        if os.path.exists(input_path):
            os.remove(input_path)
        if os.path.exists(input_path + ".meta"):
            os.remove(input_path + ".meta")


def calc_bbs_and_do_deduplication(ta_dir, coverage_path, enable_del=False):
    pattern = re.compile(
        r"TA_GP_emulator/(?P<tee>[^/]+)/harness/(?P<group_name>[^/]+)/out/cov"
    )
    hash_bbs = set()
    same_cov_collection = {}
    cnt = 0
    for file in os.listdir(coverage_path):
        match = pattern.search(os.path.join(coverage_path, file))
        if match:
            tee = match.group("tee")
            group_name = match.group("group_name")
            bbs: List[BB] = sorted(
                [
                    str(bb)
                    for bb in parse_drcov(
                        tee, group_name, os.path.join(coverage_path, file)
                    )
                ]
            )
            hash_bb = hashlib.sha256(str(bbs).encode()).hexdigest()
            if hash_bb in hash_bbs:
                if enable_del:
                    del_duplicate(os.path.join(ta_dir, "in", "suspicious_inputs", file[: -len(".cov")]))
                else:
                    print(f"[-] Found duplicate coverage hash: {hash_bb} for {ta_dir}\n")
                same_cov_collection[hash_bb].append(os.path.join(coverage_path, file))
            else:
                cnt += 1
                hash_bbs.add(hash_bb)
                same_cov_collection[hash_bb] = [os.path.join(coverage_path, file)]
    print(f"Total unique coverage hashes: {cnt} under {ta_dir}")
    print(json.dumps(same_cov_collection, indent=4))


async def async_replay(ta_dir, input_path, container_id):
    proc = await asyncio.create_subprocess_shell(
        f'docker exec -it emu_{container_id} ./fuzz.sh {ta_dir.replace("/root/TA_GP_emulator/", "../")} {input_path.replace("/root/TA_GP_emulator/", "../")}',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        print(f"[-] Error replaying {input_path} with error: {stdout.decode('utf-8')}")
        raise Exception(
            f"Error replaying {input_path} with error: {stdout.decode('utf-8')}"
        )
    elif b"place_input returned -1" in stdout:
        return False
    else:
        return True


async def coverage_based_deduplicate(group_dir, one_group_inputs, enable_del=False, num_replay_containers=5):
    print(f"Processing {len(one_group_inputs)} inputs under {group_dir}\n")
    group_dir = group_dir.replace("/in", "")
    results = []
    one_group_inputs = [item for item in one_group_inputs if not item.endswith(".meta")]
    
    batch_size = num_replay_containers * 10
    for i in tqdm.tqdm(range(0, len(one_group_inputs), batch_size), desc=f"[^] Replaying {group_dir}:"):
        if i != 0:
            await asyncio.sleep(3)
        batch = one_group_inputs[i:min(i + batch_size, len(one_group_inputs))]
        print(f"[+] {time.strftime('%Y-%m-%d %H:%M:%S')} Replaying {i} -> {min(i + len(batch), len(one_group_inputs))} inputs under {group_dir}\n")
        tasks = [async_replay(group_dir, input_path, (i + j) % num_replay_containers) for j, input_path in enumerate(batch)]
        results.extend(await asyncio.gather(*tasks, return_exceptions=True))

    if True in results:
        calc_bbs_and_do_deduplication(
            group_dir, os.path.join(group_dir, "out", "cov"), enable_del=enable_del
        )


async def async_read_records(path, conservative=True):
    try:
        async with aiofiles.open(path, "r") as f:
            data = await f.read()
            data = json.loads(data.decode("utf-8"))
            key_data_records = list[Any](item for item in data["records"])
            if not conservative:
                key_data_records = [record["regs"] for record in key_data_records]
            return hashlib.sha256(str(key_data_records).encode()).hexdigest()
    except Exception as e:
        print(f"[-] Error processing path: {path} with error: {e}")
        raise e


async def control_flow_based_deduplicate(
    group_dir, one_group_inputs, conservative=True, enable_del=False
):
    print(f"Processing {len(one_group_inputs)} inputs under {group_dir}")
    cnt = 0
    tasks = {}
    control_flow_hashes = set()
    for path in one_group_inputs:
        if not path.endswith(".meta"):
            continue
        tasks[path] = async_read_records(path, conservative)
    hash_values = await asyncio.gather(*tasks.values(), return_exceptions=True)

    for path, hash_value in zip(tasks.keys(), hash_values):
        if isinstance(hash_value, Exception):
            print(f"[-] Error processing path: {path} with error: {hash_value}")
            continue

        if hash_value in control_flow_hashes:
            if enable_del:
                del_duplicate(path)
            else:
                print(f"[-] Found duplicate control flow hash: {hash_value} for {path}")
        else:
            cnt += 1
            control_flow_hashes.add(hash_value)
    print(f"Total unique control flow hashes: {cnt} under {group_dir}")


def group_pair(suspicious_input_paths):
    grouped_inputs = {}
    for path in suspicious_input_paths:
        base_dir = os.path.dirname(path).replace("suspicious_inputs", "")
        if base_dir not in grouped_inputs:
            grouped_inputs[base_dir] = []
        grouped_inputs[base_dir].append(path)
    return grouped_inputs


def shut_down(num_replay_containers, mode):
    if mode == "coverage":
        print("[+] Stopping emulator container")
        for i in range(num_replay_containers):
            subprocess.run(f"docker stop emu_{i}", shell=True)
            subprocess.run(f"docker rm emu_{i}", shell=True)
        print("[+] Emulator containers stopped")
        exit(0)


async def main(mode, grouped_inputs, enable_del=False, num_replay_containers=5):
    for key, value in grouped_inputs.items():
        if mode == "control_flow":
            await control_flow_based_deduplicate(
                key,
                value,
                conservative=not args.non_conservative,
                enable_del=enable_del,
            )
        elif mode == "coverage":
            await coverage_based_deduplicate(key, value, enable_del=enable_del, num_replay_containers=num_replay_containers)
    print("[+] Deduplication completed")


def validate(args):
    if os.path.exists("/.dockerenv"):
        print("[-] ERROR! Please run deduplicate.py outside of the emulator container")
        exit(3)

    if args.mode == "coverage":
        ps = subprocess.run("docker ps", shell=True, capture_output=True)
        if "emu" not in str(ps.stdout):
            print("[-] Coverage mode is not supported with emulator container")
            print(
                "[-] Do you want to launch the emulator container and continue? (y/N)"
            )
            reply = input().lower()
            if reply == "y":
                for i in range(args.num_replay_containers):
                    subprocess.run(
                        f"docker run -d --name emu_{i} --network host -it -v .:/srv -w /srv/emulator -v /dev/shm:/dev/shm --ipc=host --shm-size=100g ta_emu bash &>/dev/null",
                        shell=True,
                    )
            else:
                print("[-] Exiting...")
                exit(2)
    time.sleep(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, default="/root/TA_GP_emulator")
    parser.add_argument("--enable-del", action="store_true", default=False)
    parser.add_argument("--non-conservative", action="store_true", default=False)
    parser.add_argument(
        "--mode", type=str, default="control_flow", choices=["control_flow", "coverage"]
    )
    parser.add_argument("--num-replay-containers", type=int, default=5)
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, lambda signal, frame: shut_down(args.num_replay_containers, args.mode))
    signal.signal(signal.SIGTERM, lambda signal, frame: shut_down(args.num_replay_containers, args.mode))
    
    print(
        "[+] Processing path: {} on {}-based deduplication mode with {}conservative type and {}del type".format(
            args.path,
            args.mode,
            "non-" if args.non_conservative else "",
            "" if args.enable_del else "non-",
        )
    )
    validate(args)

    suspicious_input_paths = get_all_suspicious_inputs(args.path)
    grouped_inputs = group_pair(suspicious_input_paths)
    asyncio.run(main(args.mode, grouped_inputs, enable_del=args.enable_del, num_replay_containers=args.num_replay_containers))
    shut_down(args.num_replay_containers, args.mode)