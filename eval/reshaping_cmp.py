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
    def __init__(self, harness_path, duration, df_out, sus_out=None):
        self.harness_path = harness_path
        self.duration = duration
        self.df_out_path = df_out
        self.sus_out_path = sus_out

def to_emu_name(i):
    return f'emu_{i}'

def fuzz(i, job):
    emu_name = to_emu_name(i)
    if job.duration > 21600:
        fuzz_time = job.duration // 10
        fuzz_script = 'fuzz_hack_multicore.sh'
    else:
        fuzz_time = job.duration
        fuzz_script = 'fuzz_hack.sh'
    print(f'fuzzing {job.harness_path}', flush=True)
    t1 = time.time()
    print(f'timeout -k {fuzz_time} {fuzz_time} docker exec {emu_name} ./{fuzz_script} {job.harness_path.replace("/root/TA_GP_emulator/", "../")}', flush=True)
    proc = subprocess.run(
        f'timeout -k {fuzz_time} {fuzz_time} docker exec {emu_name} ./{fuzz_script} {job.harness_path.replace("/root/TA_GP_emulator/", "../")}', shell=True, capture_output=True
    )
    print(proc.stdout, flush=True)
    print(proc.stderr, flush=True)
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
                q.put(Job(harness_path, num_dfs * args.df_fuzz_time, root))
    else:
        path = os.path.join(args.fuzz_backup, 'df_fuzz')
        for harness in os.listdir(path):
            harness_path = get_harness_path(args.path, harness) 
            assert harness_path is not None
            if ignore_harness in harness_path: continue
            num_dfs = len(os.listdir(os.path.join(path, harness, 'df_fuzz')))
            print(f'[^] {harness_path} num dfs: {num_dfs} {num_dfs * args.df_fuzz_time}', flush=True)
            q.put(Job(harness_path, num_dfs * args.df_fuzz_time, os.paht.join(path, harness, 'df_fuzz'))) 

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


def analyze_task(job):
    fuzzed_sus2reghash = {} 
    fuzzed_controlflowhashes = []
    dff_execs = 0
    dff_execs_2 = 0
    done = []
    for df_out in os.listdir(job.df_out_path):
        df_seed, reg_hash = df_out.split("/")
        dff_execs += get_execs(os.path.join(df_out, 'out', 'default')) 
        if df_seed not in done:
            done.append(df_seed)
            dff_execs_2 += get_execs(os.path.join(df_out, 'out', 'default'))
    print(f'{job.harness} {dff_execs} {dff_execs_2}')
    rsh_execs = 0
    rsh_execs_df = 0
    for out in os.listdir(os.path.join(job.harness_path, 'out')):
        rsh_execs += get_execs(os.path.join(job.harness_path, 'out', out))
    for jsson in os.listdir(os.path.join(job.harness_path, 'record_meta')):
        if jsson.endswith('hash2count.json'):
            a = json.load(os.path.join(job.harness_path, 'record_meta', jsson))
            for k,v in a.items():
                rsh_execs_df  += v
    print(f'{job.harness} {rsh_execs} {rsh_execs_df}')

def print_numbers(args):
    gather_jobs(args)  
    while True:
        try:
            job = q.get_nowait()
        except queue.Empty:
            break
        analyze_task(job)
        q.task_done()
     

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, default="/root/TA_GP_emulator")
    parser.add_argument("--fuzz-backup", type=str, required=False, help="if set will use fuzzing backup data from this path")
    parser.add_argument("--df-fuzz-time", type=int, default=15*60, required=False, help="time for df-fuzzing")
    parser.add_argument("--num-containers", type=int, default=5)
    parser.add_argument("--print-numbers", action="store_true", default=False)
    
    args = parser.parse_args()
    
    if "eval" in os.getcwd() or "TA_GP_emulator" not in os.getcwd():
        print(f"[-] Please run deduplicate.py at /{os.getlogin()}/TA_GP_emulator")
        exit(1)
    
    os.system(f'docker rm -f $(docker ps -aq)')

    if args.print_numbers:
        print_numbers(args)
        exit(0)
    
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
