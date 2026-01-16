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


def get_all_crashes(path="/root/TA_GP_emulator"):
    df_crashes = []
    invalid_exits = []
    for root, dirs, files in os.walk(path):
        for file in files:
            path = os.path.join(root, file)
            if "df_fuzz" in path and "out/default/crashes" in path:
                if path.endswith(".output"): 
                    afl_crash = open(path, "rb").read()
                    if b"Fork server handshake failed" in afl_crash:
                        invalid_exits.append(path.strip(".output"))
                    continue
                if path.endswith("README.txt"): continue
                if path.endswith(".df"): continue
                df_crashes.append(path)
    df_crashes = list(set(df_crashes)-set(invalid_exits))
    return df_crashes

def df_seed_from_crash(ta_dir, df_fuzz_crash):
    parts = df_fuzz_crash.split("/")
    for i, part in enumerate(parts):
        if part == "df_fuzz":
            run_part = parts[i+1]
            sus = run_part.split("_")[0]
            reg_hash = run_part.split("_")[-1]
            return os.path.join(ta_dir, "in", "suspicious_inputs_replay", sus)
    return None

def reg_hash_from_crash(ta_dir, df_fuzz_crash):
    parts = df_fuzz_crash.split("/")
    for i, part in enumerate(parts):
        if part == "df_fuzz":
            run_part = parts[i+1]
            sus = run_part.split("_")[0]
            reg_hash = run_part.split("_")[-1]
            return reg_hash
    return None

async def async_validate(ta_dir, df_fuzz_crash, df_seed, reg_hash, container_id):
    proc = await asyncio.create_subprocess_shell(
        f'docker exec emu_{container_id} ./df_validate.sh {ta_dir.replace("/root/TA_GP_emulator/", "../")} {df_seed.replace("/root/TA_GP_emulator/", "../")} {reg_hash} {df_fuzz_crash.replace("/root/TA_GP_emulator", "../")}',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return stdout+stderr
    if proc.returncode != 0:
        print(f"[-] Error validating {df_seed} {df_fuzz_crash} with error: {stdout.decode('utf-8')}; {stderr.decode('utf-8')}")
        raise Exception(
            f"Error validating {df_seed} {df_fuzz_crash} with error: {stdout.decode('utf-8')}; {stderr.decode('utf-8')}"
        )
    elif b"place_input returned -1" in stdout:
        return stdout+stderr
    else:
        return 


async def validate_df_crashes(group_dir, one_group_inputs, num_replay_containers=10):
    print(f"Processing {len(one_group_inputs)} inputs under {group_dir}\n")
    ta_dir = os.path.normpath(os.path.join(group_dir, "..", ".."))
    results = []
    one_group_inputs = [item for item in one_group_inputs]
    
    reuse_ratio = 1 # number of replays who reuse the same container [for stability]
    batch_size = num_replay_containers * reuse_ratio 
    for i in tqdm.tqdm(range(0, len(one_group_inputs), batch_size), desc=f"[^] Validating {ta_dir}:"):
        if i != 0:
            await asyncio.sleep(5)
        batch = one_group_inputs[i:min(i + batch_size, len(one_group_inputs))]
        print(batch)
        print(f"[+] {time.strftime('%Y-%m-%d %H:%M:%S')} Replaying {i} -> {min(i + len(batch), len(one_group_inputs))} inputs under {group_dir}\n")
        for df_fuzz_crash in batch:
            df_seed = df_seed_from_crash(ta_dir, df_fuzz_crash)
            reg_hash = reg_hash_from_crash(ta_dir, df_fuzz_crash)
            print(f'docker exec emu ./df_validate.sh {ta_dir.replace("/root/TA_GP_emulator/", "../")} {df_seed.replace("/root/TA_GP_emulator/", "../")} {reg_hash} {df_fuzz_crash.replace("/root/TA_GP_emulator", "../")}')
        tasks = [async_validate(ta_dir, arg, df_seed_from_crash(ta_dir, arg), reg_hash_from_crash(ta_dir, arg), (i + j) % num_replay_containers) for j, arg in enumerate(batch)]
        results.extend(await asyncio.gather(*tasks, return_exceptions=True))

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


def group_pair(df_crashes_paths):
    grouped_inputs = {}
    for path in df_crashes_paths:
        base_dir = os.path.dirname(path).replace("out/default/crashes", "")
        if base_dir not in grouped_inputs:
            grouped_inputs[base_dir] = []
        grouped_inputs[base_dir].append(path)
    return grouped_inputs


def shut_down(num_replay_containers):
    print("[+] Stopping emulator container")
    for i in range(num_replay_containers):
        subprocess.run(f"docker stop emu_{i}", shell=True)
        subprocess.run(f"docker rm emu_{i}", shell=True)
    print("[+] Emulator containers stopped")
    
    exit(0)


async def main(grouped_inputs, num_replay_containers=10):
    for key, value in grouped_inputs.items():
        await validate_df_crashes(key, value, num_replay_containers=num_replay_containers)
    print("[+] Validation completed")


def validate(args):
    if os.path.exists("/.dockerenv"):
        print("[-] ERROR! Please run deduplicate.py outside of the emulator container")
        exit(3)

    ps = subprocess.run("docker ps", shell=True, capture_output=True)
    if "emu_" not in str(ps.stdout):
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
    print("[+] Emulator containers started")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, default="/root/TA_GP_emulator")
    parser.add_argument("--tee", type=str, default="all")
    parser.add_argument("--num-replay-containers", type=int, default=20)
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, lambda signal, frame: shut_down(args.num_replay_containers))
    signal.signal(signal.SIGTERM, lambda signal, frame: shut_down(args.num_replay_containers))
    
    if "eval" in os.getcwd() or "TA_GP_emulator" not in os.getcwd():
        print(f"[-] Please run deduplicate.py at /{os.getlogin()}/TA_GP_emulator")
        exit(1)
    
    validate(args)

    df_crash_paths = get_all_crashes(args.path)
    grouped_inputs = group_pair(df_crash_paths)
    if args.tee != "all":
        grouped_inputs = {k: v for k, v in grouped_inputs.items() if args.tee in k}

    asyncio.run(main(grouped_inputs, num_replay_containers=args.num_replay_containers))
    shut_down(args.num_replay_containers)
    