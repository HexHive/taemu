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
import threading
import queue

ignore_harness = "86f6_fuzz"


q = queue.Queue() 

class Job:
    def __init__(self, harness_path, duration):
        self.harness_path = harness_path
        self.duration = duration

def to_emu_name(i):
    return f'emu_{i}'

def fuzz(i, job):
    emu_name = to_emu_name(i)
    if job.duration > 21600:
        fuzz_time = job.duration // 10
        fuzz_script = 'fuzz_multicore.sh'
    else:
        fuzz_time = job.duration
        fuzz_script = 'fuzz.sh'
    print(f'fuzzing {job.harness_path}', flush=True)
    t1 = time.time()
    proc = subprocess.run(
        f'timeout -k {fuzz_time} {fuzz_time} docker exec {emu_name} ./{fuzz_script} {job.harness_path.replace("/root/TA_GP_emulator/", "../")}', shell=True, capture_output=True
    )
    elapsed = time.time() - t1
    print(f'fuzzed {job.harness_path} {fuzz_time} -> {elapsed}', flush=True)

def worker(i):
    while True:
        try:
            job = q.get_nowait()
        except queue.Empty:
            break
        fuzz(i, job)
        q.task_done()

def get_harness_path(path, harness_dir):
    for root, dirs, files in os.walk(path):
        if os.path.basename(root) == harness_dir:
            return root
    return None

def gather_jobs(args):
    if args.fuzz_backup is None:
        path = args.path
        for root, dirs, files in os.walk(path):
            if os.path.basename(root) == "df_fuzz":
                harness_path = os.path.normpath(os.path.join(root, ".."))
                if ignore_harness in harness_path: continue
                num_dfs = len(os.listdir(root))
                print(f'[^] {harness_path} num dfs: {num_dfs}', flush=True)
                q.put(Job(harness_path, num_dfs * args.df_fuzz_time))
    else:
        path = os.path.join(args.fuzz_backup, 'df_fuzz')
        for harness in os.listdir(path):
            harness_path = get_harness_path(args.path, harness) 
            assert harness_path is not None
            if ignore_harness in harness_path: continue
            num_dfs = len(os.listdir(os.path.join(path, harness, 'df_fuzz')))
            print(f'[^] {harness_path} num dfs: {num_dfs} {num_dfs * args.df_fuzz_time}', flush=True)
            q.put(Job(harness_path, num_dfs * args.df_fuzz_time)) 

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
            for i in range(args.num_containers):
                subprocess.run(
                    f"docker run -d --name emu_{i} --network host -it -v .:/srv -w /srv/emulator -v /dev/shm:/dev/shm --ipc=host --shm-size=100g ta_emu bash &>/dev/null",
                    shell=True,
                )
        else:
            print("[-] Exiting...")
            exit(2)
    if "redis" not in str(ps.stdout):
        print("[-] Redis container is not running")
        print("[-] Do you want to launch the Redis container and continue? (y/N)")
        reply = input().lower()
        if reply == "y":
            subprocess.run(
                "docker compose -f docker-compose.redis.yml up -d", shell=True
            )
        else:
            print("[-] Exiting...")
    time.sleep(5)
    print("[+] Emulator containers started")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, default="/root/TA_GP_emulator")
    parser.add_argument("--fuzz-backup", type=str, required=False, help="if set will use fuzzing backup data from this path")
    parser.add_argument("--df-fuzz-time", type=int, default=15*60, required=False, help="time for df-fuzzing")
    parser.add_argument("--num-containers", type=int, default=15)
    
    args = parser.parse_args()
    
    if "eval" in os.getcwd() or "TA_GP_emulator" not in os.getcwd():
        print(f"[-] Please run deduplicate.py at /{os.getlogin()}/TA_GP_emulator")
        exit(1)
    
    validate(args)

    gather_jobs(args)
    threads = []
    for i in range(args.num_containers):
        threads.append(threading.Thread(target=worker, args=[i,]))

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    q.join()