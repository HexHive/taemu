# Backup side-road deduplication

import json
import random
import os

import argparse
import asyncio
from typing import Any, List
import re
import subprocess
import signal
import hashlib
import sys
import struct

import time
import tqdm
import aiofiles
import taemu_env
from graphs.common import parse_drcov
from graphs.common import BB

MIN_DRCOV_FILE_SIZE = 20
DRCOV_VERSION = 2

DRCOV_HEADER_RE = r"DRCOV VERSION: (?P<version>\d+)\n"
MODULE_HEADER_V2_RE = (
    r"Module Table: version (?P<version>\d+), count (?P<mod_num>\d+)\n"
)
BB_HEADER_RE = r"BB Table: (?P<bbcount>\d+) bbs\n"


def get_all_suspicious_inputs(path=None):
    path = path or taemu_env.repo_root()
    suspicious_inputs = []
    for root, dirs, files in os.walk(path):
        for file in files:
            path = os.path.join(root, file)
            if "suspicious_inputs/" in path and "harness_dev" not in path:
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
        r"/(?P<tee>[^/]+)/harness/(?P<group_name>[^/]+)/out/cov"
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
                    del_duplicate(
                        os.path.join(
                            ta_dir, "in", "suspicious_inputs", file[: -len(".cov")]
                        )
                    )
                    del_duplicate(
                        os.path.join(
                            ta_dir,
                            "in",
                            "suspicious_inputs_replay",
                            file[: -len(".cov")],
                        )
                    )
                else:
                    print(
                        f"[-] Found duplicate coverage hash: {hash_bb} for {ta_dir}\n"
                    )
                same_cov_collection[hash_bb].append(os.path.join(coverage_path, file))
            else:
                cnt += 1
                hash_bbs.add(hash_bb)
                same_cov_collection[hash_bb] = [os.path.join(coverage_path, file)]
    print(f"Total unique coverage hashes: {cnt} under {ta_dir}")
    print(json.dumps(same_cov_collection, indent=4))


async def async_replay(ta_dir, input_path, container_id):
    proc = await asyncio.create_subprocess_shell(
        f'docker exec {taemu_env.emu_name(container_id)} ./replay_sus.sh {taemu_env.to_emulator_rel(ta_dir)} {taemu_env.to_emulator_rel(input_path)}',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        print(
            f"[-] Error replaying {input_path} with error: {stdout.decode('utf-8')}; {stderr.decode('utf-8')}"
        )
        raise Exception(
            f"Error replaying {input_path} with error: {stdout.decode('utf-8')}; {stderr.decode('utf-8')}"
        )
    elif b"place_input returned -1" in stdout:
        return False
    else:
        return True


async def coverage_based_deduplicate(
    group_dir, one_group_inputs, enable_del=False, num_replay_containers=10
):
    print(f"Processing {len(one_group_inputs)} inputs under {group_dir}\n")
    group_dir = group_dir.replace("/in", "")
    results = []
    one_group_inputs = [item for item in one_group_inputs if not item.endswith(".meta")]

    # Every worker container is kept busy: a container is handed to the next
    # input as soon as it is free. This used to run in barriered batches with a
    # fixed 5 s sleep between them, so with N containers and M inputs it spent
    # M/N * 5 s doing nothing and idled whenever one replay in a batch was slow.
    free = asyncio.Queue()
    for cid in range(num_replay_containers):
        free.put_nowait(cid)

    async def replay_one(input_path):
        cid = await free.get()
        try:
            return await async_replay(group_dir, input_path, cid)
        finally:
            free.put_nowait(cid)

    print(f"[+] replaying {len(one_group_inputs)} inputs on "
          f"{num_replay_containers} containers under {group_dir}")
    results = await asyncio.gather(
        *(replay_one(p) for p in one_group_inputs), return_exceptions=True
    )

    if True in results:
        calc_bbs_and_do_deduplication(
            group_dir, os.path.join(group_dir, "out", "cov"), enable_del=enable_del
        )


async def async_read_records(path, conservative=True):
    try:
        async with aiofiles.open(path, "r") as f:
            data = await f.read()
            data = json.loads(data)
            key_data_records = list[Any](item for item in data["records"])
            if not conservative:
                key_data_records = [record["regs"] for record in key_data_records]
            return hashlib.sha256(str(key_data_records).encode()).hexdigest()
    except Exception as e:
        print(f"[-] Error processing path: {path} with error: {e}")
        raise e


async def control_flow_based_deduplicate(
    group_dir,
    one_group_inputs,
    conservative=True,
    enable_del=False,
    max_concurrent_tasks=50,
):
    print(f"Processing {len(one_group_inputs)} inputs under {group_dir}")
    cnt = 0
    control_flow_hashes = set()

    # Filter to only .meta files
    meta_paths = [path for path in one_group_inputs if path.endswith(".meta")]

    # Process in batches to control concurrency
    batch_size = max_concurrent_tasks
    for i in tqdm.tqdm(
        range(0, len(meta_paths), batch_size), desc=f"[^] Reading records {group_dir}:"
    ):
        batch = meta_paths[i : min(i + batch_size, len(meta_paths))]
        tasks = {path: async_read_records(path, conservative) for path in batch}
        hash_values = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for path, hash_value in zip(tasks.keys(), hash_values):
            if isinstance(hash_value, Exception):
                print(f"[-] Error processing path: {path} with error: {hash_value}")
                continue

            if hash_value in control_flow_hashes:
                if enable_del:
                    del_duplicate(path)
                    # TODO: delete the corresponding suspicious_inputs_replay file
                else:
                    print(
                        f"[-] Found duplicate control flow hash: {hash_value} for {path}"
                    )
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
            subprocess.run(f"docker stop {taemu_env.emu_name(i)}", shell=True)
            subprocess.run(f"docker rm {taemu_env.emu_name(i)}", shell=True)
        print("[+] Emulator containers stopped")

        if os.environ.get("TAEMU_KEEP_REDIS"):
            print("[+] Leaving the redis container running (TAEMU_KEEP_REDIS)")
        else:
            print("[+] Stopping Redis container")
            subprocess.run("docker stop ta_emulator_redis_ui", shell=True)
            subprocess.run("docker rm ta_emulator_redis_ui", shell=True)
            subprocess.run("docker stop ta_emulator_redis", shell=True)
            subprocess.run("docker rm ta_emulator_redis", shell=True)
            print("[+] Redis container stopped")
        exit(0)


async def main(mode, grouped_inputs, enable_del=False, num_replay_containers=10):
    for key, value in grouped_inputs.items():
        if mode == "control_flow":
            await control_flow_based_deduplicate(
                key,
                value,
                conservative=not args.non_conservative,
                enable_del=enable_del,
            )
        elif mode == "coverage":
            await coverage_based_deduplicate(
                key,
                value,
                enable_del=enable_del,
                num_replay_containers=num_replay_containers,
            )
    print("[+] Deduplication completed")


def validate(args):
    taemu_env.require_docker()

    if args.mode == "coverage":
        if not taemu_env.redis_container_running():
            print("[-] Redis container is not running")
            print("[-] Do you want to launch the Redis container and continue? (y/N)")
            reply = input().lower()
            if reply == "y":
                subprocess.run(
                    f"docker compose -f {os.path.join(taemu_env.repo_root(), 'docker-compose.redis.yml')} up -d",
                    shell=True,
                )
            else:
                print("[-] Exiting...")
        if not taemu_env.emulator_containers_running():
            print("[-] Coverage mode is not supported with emulator container")
            print(
                "[-] Do you want to launch the emulator container and continue? (y/N)"
            )
            reply = input().lower()
            if reply == "y":
                for i in range(args.num_replay_containers):
                    r = subprocess.run(
                        taemu_env.emulator_container_cmd(taemu_env.emu_name(i)),
                        shell=True, capture_output=True,
                    )
                    if r.returncode != 0:
                        print(f"[-] could not start {taemu_env.emu_name(i)}: "
                              f"{r.stderr.decode(errors='replace').strip()}")
            else:
                print("[-] Exiting...")
                exit(2)
    time.sleep(5)
    print("[+] Emulator containers started")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, default=taemu_env.repo_root())
    parser.add_argument("--tee", type=str, default="all")
    parser.add_argument("--enable-del", action="store_true", default=False)
    parser.add_argument("--non-conservative", action="store_true", default=False)
    parser.add_argument(
        "--mode", type=str, default="control_flow", choices=["control_flow", "coverage"]
    )
    parser.add_argument("--num-replay-containers", type=int, default=20)
    parser.add_argument("--per-harness-limit", type=int, required=False)

    args = parser.parse_args()

    signal.signal(
        signal.SIGINT,
        lambda signal, frame: shut_down(args.num_replay_containers, args.mode),
    )
    signal.signal(
        signal.SIGTERM,
        lambda signal, frame: shut_down(args.num_replay_containers, args.mode),
    )

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
    if args.tee != "all":
        grouped_inputs = {k: v for k, v in grouped_inputs.items() if args.tee in k}
    if args.per_harness_limit is not None:
        limit = args.per_harness_limit
        grouped_inputs = {k: random.sample(v,min(len(v),limit)) for k, v in grouped_inputs.items()}
        print(grouped_inputs)

    asyncio.run(
        main(
            args.mode,
            grouped_inputs,
            enable_del=args.enable_del,
            num_replay_containers=args.num_replay_containers,
        )
    )
    shut_down(args.num_replay_containers, args.mode)


# def del_duplicate(path, left_inputs):
#     for file in os.listdir(path):
#         if file not in left_inputs:
#             # print(f"[-] Deleting {os.path.join(path, file)}")^(?!t6).+
#             os.remove(os.path.join(path, file))

# for dir, _, files in os.walk("/root/TA_GP_emulator"):
#     if dir.endswith("suspicious_inputs") and not dir.endswith("suspicious_inputs_replay"):
#         fuzz_harness_dir = dir.split("/")[-3]
#         left_inputs = []
#         for file in files:
#             left_inputs.append(file)
#         if os.path.exists(dir.replace("suspicious_inputs", "suspicious_inputs_replay")):
#             del_duplicate(dir.replace("suspicious_inputs", "suspicious_inputs_replay"), left_inputs)
        
