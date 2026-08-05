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


def get_all_crashes(path=None):
    path = path or taemu_env.repo_root()
    df_crashes = []
    invalid_exits = []
    for root, dirs, files in os.walk(path):
        for file in files:
            path = os.path.join(root, file)
            if "/df_fuzz/" in path and "out/default/crashes" in path:
                if path.endswith(".output"): 
                    afl_crash = open(path, "rb").read()
                    if b"Fork server handshake failed" in afl_crash or b"Fork server crashed with signal 7" in afl_crash:
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
        f'docker exec {taemu_env.emu_name(container_id)} ./df_validate.sh {taemu_env.to_emulator_rel(ta_dir)} {taemu_env.to_emulator_rel(df_seed)} {reg_hash} {taemu_env.to_emulator_rel(df_fuzz_crash)}',
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
    
    # Same as in deduplicate.py: keep every container busy instead of running
    # barriered batches with a fixed sleep in between.
    free = asyncio.Queue()
    for cid in range(num_replay_containers):
        free.put_nowait(cid)

    async def validate_one(crash):
        cid = await free.get()
        try:
            return await async_validate(ta_dir, crash, df_seed_from_crash(ta_dir, crash),
                                        reg_hash_from_crash(ta_dir, crash), cid)
        finally:
            free.put_nowait(cid)

    print(f"[+] validating {len(one_group_inputs)} crashes on "
          f"{num_replay_containers} containers under {group_dir}")
    results = await asyncio.gather(
        *(validate_one(c) for c in one_group_inputs), return_exceptions=True
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
        subprocess.run(f"docker stop {taemu_env.emu_name(i)}", shell=True)
        subprocess.run(f"docker rm {taemu_env.emu_name(i)}", shell=True)
    print("[+] Emulator containers stopped")
    
    exit(0)


async def main(grouped_inputs, num_replay_containers=10):
    for key, value in grouped_inputs.items():
        await validate_df_crashes(key, value, num_replay_containers=num_replay_containers)
    print("[+] Validation completed")


def validate(args):
    taemu_env.require_docker()

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
    parser.add_argument("--num-replay-containers", type=int, default=20)
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, lambda signal, frame: shut_down(args.num_replay_containers))
    signal.signal(signal.SIGTERM, lambda signal, frame: shut_down(args.num_replay_containers))
    
    validate(args)

    df_crash_paths = get_all_crashes(args.path)
    grouped_inputs = group_pair(df_crash_paths)
    if args.tee != "all":
        grouped_inputs = {k: v for k, v in grouped_inputs.items() if args.tee in k}

    asyncio.run(main(grouped_inputs, num_replay_containers=args.num_replay_containers))
    shut_down(args.num_replay_containers)
    
