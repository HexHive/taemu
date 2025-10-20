import threading
import json
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import queue
import os
import time
import subprocess
import sys

from bb import build_tee_cfg
from fuzz import FUZZ_TIME, TEES, FUZZ_ITERATIONS, FUZZ_CHUNKS

root = 8*"0"
BASE = os.path.join(os.path.dirname(__file__), "..")
COV_API_DIR = "api_cov"

"""
After a fuzzing campaign, replay all generated seeds against the emulator with different implemented APIs
x-axis: time
y-axis: coverage
"""

def do_work(harness_path, apis, api_order_name):
    cov_api = os.path.join(harness_path, COV_API_DIR)
    drcov_file  = os.path.join(harness_path, "drcov.log")
    if not os.path.exists(cov_api):
        os.system(f'mkdir -p {cov_api}')
    api_order_path = os.path.join(cov_api, api_order_name)
    if os.path.exists(api_order_path):
        os.system(f'rm -rf {api_order_path}')
    os.system(f'mkdir -p {api_order_path}')

    # move all prior seeds into appropriate queue folder
    out_path = os.path.join(harness_path, 'out', 'default', 'queue')
    os.system(f'mkdir -p {out_path}')
    campaign_dir = os.path.join(harness_path, "campaign_out")
    for iteration in range(0, FUZZ_ITERATIONS):
        api_order_iteration_path = os.path.join(api_order_path, str(iteration))
        os.system(f'mkdir -p {api_order_iteration_path}')
        if FUZZ_TIME > 60*60:
            fuzz_chunks = os.path.join(campaign_dir, str(iteration), FUZZ_CHUNKS)
            for j in os.listdir(fuzz_chunks):
                chunk_dir = os.path.join(fuzz_chunks, j, "queue")
                os.system(f'cp {chunk_dir}/* {out_path}/')
        else:
            os.system(f'cp {campaign_dir}/{iteration}/queue/* {out_path}/')
        implemented_apis = []
        i = 0
        tmp_path = os.path.join(harness_path, f'impl_apis.json')
        while len(implemented_apis) <= len(apis):
            json.dumps(open(tmp_path, "w+"), implemented_apis)
            if os.path.exists(drcov_file):
                os.system(f'rm {drcov_file}')
            out_dir = os.path.join(api_order_iteration_path, str(len(implemented_apis)))
            os.system(f'mkdir -p {out_dir}')
            proc = subprocess.run(f'docker exec -it emu ./replay_api.sh ../{harness_path} {tmp_path}', shell=True, capture_output=True)
            os.system(f'mv {drcov_file} {out_dir}/')
            implemented_apis.append(apis[i])
            i += 1
        os.system(f'rm -rf {out_path}/*')

def thread_worker(q: queue.Queue):
    while True:
        try:
            job = q.get(block=False)
        except queue.Empty:
            break
        try:
            do_work(job[0], job[1])
        finally:
            q.task_done()

def main():
    if 'emu' not in str(subprocess.run('docker ps', shell=True)):
        subprocess.run(f'cd {BASE}  && docker run --rm --name emu --network host -d -v .:/srv -w /srv/emulator -v /dev/shm:/dev/shm --ipc=host --shm-size=100g ta_emu tail -f', shell=True)
    num_cores = os.cpu_count() or 2
    num_threads = max(1, num_cores - 5)  # at least 1 thread
    print(f"Using {num_threads} threads")
    job_queue = queue.Queue()
    all_api_order = open(os.path.join(BASE, "eval", "bbs_out", f'all_order.txt')).read().split('\n')
    for tee in TEES:
        tee_api_order = open(os.path.join(BASE, "eval", "bbs_out", f'{tee}_order.txt')).read().split('\n')
        for harness in os.listdir(os.path.join(BASE, tee, "harness")):
            if harness == "__pycache__": continue
            if not os.path.exists(os.path.join(BASE, tee, "harness", harness, "ta.txt")):
                print(f'!!!!!! {os.path.join(BASE, tee, "harness", harness)} has no ta.txt!!!!!')
                exit(-1)
            if os.path.exists(os.path.join(BASE, tee, "harness", harness, "IGNOREME")):
                continue
            ta_name = open(os.path.join(BASE, tee, "harness", harness, "ta.txt")).read().strip("\n")
            if not os.path.exists(os.path.join(BASE, tee, "harness", harness, ta_name)):
                os.symlink(os.path.join("..", "..", "tas", ta_name), os.path.join("..", tee, "harness", harness, ta_name))
                os.symlink(os.path.join("..", "..", "tas", ta_name[:-3]+".json"), os.path.join("..", tee, "harness", harness, ta_name[:-3]+".json"))

            job_queue.put(
                (os.path.join(tee, "harness", harness), tee_api_order, "tee_api_order")
            )
            job_queue.put(
                (os.path.join(tee, "harness", harness), all_api_order, "all_api_order")
            )

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=thread_worker, args=(job_queue,))
        t.start()
        time.sleep(1)
        threads.append(t)
    job_queue.join()
    for t in threads:
        t.join()

    print("All jobs completed")

if __name__ == "__main__":
    main()
