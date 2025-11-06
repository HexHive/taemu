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
from fuzz import FUZZ_TIME, TEES,  FUZZ_CHUNKS

root = 8*"0"
BASE = os.path.join(os.path.dirname(__file__), "..")
COV_API_DIR = "api_cov"
REPLAY_TIMEOUT = 60

"""
After a fuzzing campaign, replay all generated seeds against the emulator with different implemented APIs
x-axis: time
y-axis: coverage
"""

def get_teamu_impl(tee_apis, tee):
    emulator_path = os.path.join(BASE, "emulator", "emulate")
    if tee == "beanpod":
        blob = open(os.path.join(emulator_path, "beanpod_api.py")).read()
    elif tee == "mitee":
        blob = open(os.path.join(emulator_path, "mitee_api.py")).read()
    elif tee == "t6":
        blob = open(os.path.join(emulator_path, "t6_api.py")).read()
    elif tee == "teegris":
        blob = open(os.path.join(emulator_path, "teegris_api.py")).read()
    elif tee == "all":
        blob = open(os.path.join(emulator_path, "beanpod_api.py")).read()
        blob += open(os.path.join(emulator_path, "mitee_api.py")).read()
        blob += open(os.path.join(emulator_path, "t6_api.py")).read()
        blob += open(os.path.join(emulator_path, "teegris_api.py")).read()
    out = []
    for api in tee_apis:
        if f'def {api}(ql' in blob:
            out.append(api)
    print(f'teamue imlemented apis: {out}')
    return out

def do_work(harness_path, campaigns, apis, api_order_name):
    print(f'doing {harness_path}')
    log_path = os.path.join(BASE, harness_path, "logs")
    if not os.path.exists(log_path):
        os.system(f'mkdir -p {log_path}')
    cov_api = os.path.join(BASE, harness_path, COV_API_DIR)
    drcov_file  = os.path.join(BASE, harness_path, "drcov.log")
    if not os.path.exists(cov_api):
        os.system(f'mkdir -p {cov_api}')
    api_order_path = os.path.join(cov_api, api_order_name)
    if os.path.exists(api_order_path):
        os.system(f'rm -rf {api_order_path}')
    os.system(f'mkdir -p {api_order_path}')

    # move all prior seeds into appropriate queue folder
    out_path = os.path.join(BASE, harness_path, 'out', 'default', 'queue')
    os.system(f'rm -rf {out_path}')
    for campaign in campaigns:
        campaign_dir = os.path.join(BASE, harness_path, campaign)
        os.system(f'mkdir -p {out_path}')
        api_order_iteration_path = os.path.join(api_order_path, campaign)
        os.system(f'mkdir -p {api_order_iteration_path}')
        if FUZZ_TIME > 60*60:
            fuzz_chunks = os.path.join(campaign_dir, FUZZ_CHUNKS)
            if not os.path.exists(fuzz_chunks):
                continue
            for j in os.listdir(fuzz_chunks):
                chunk_dir = os.path.join(fuzz_chunks, j, "queue")
                os.system(f'cp {chunk_dir}/* {out_path}/')
        else:
            os.system(f'cp {campaign_dir}/{iteration}/queue/* {out_path}/')
        implemented_apis = []
        if api_order_name == "beanpod_api_order":
            first_api = "TEE_LogPrintf"
            tee = "beanpod"
        elif api_order_name == "mitee_api_order":
            first_api = "tee_se_open_spi_clk"
            tee = "mitee"
        elif api_order_name == "t6_api_order":
            first_api = "debug_log" 
            tee = "t6"
        elif api_order_name == "teegris_api_order":
            first_api = "TEES_IsREESharedMemory"
            tee = "teegris"
        elif api_order_name == "all_api_order":
            first_api = "TEES_IsREESharedMemory"
            tee = "all"
        i = apis.index(first_api)
        implemented_apis = apis[:i]
        tee_apis = get_teamu_impl(apis[i:], tee)
        apis = implemented_apis + tee_apis
        i = apis.index(first_api)
        tmp_path = os.path.join(BASE, harness_path, f'impl_apis.json')
        tmp_path_2 = os.path.join("..", harness_path, f'impl_apis.json')
        while len(implemented_apis) < len(apis):
            print(f'{harness_path} {len(implemented_apis)}')
            open(tmp_path, "w+").write(json.dumps(implemented_apis))
            if os.path.exists(drcov_file):
                os.system(f'rm {drcov_file}')
            if not os.path.exists(f'{api_order_iteration_path}/{i}.drcov)'):
                print(f'docker exec -it emu ./replay_api.sh ../{harness_path} {tmp_path_2}')
                proc = subprocess.run(f'docker exec -e REPLAY_TIMEOUT={REPLAY_TIMEOUT} -it emu ./replay_api.sh ../{harness_path} {tmp_path_2}', shell=True, capture_output=True)
                open(os.path.join(log_path, "cov_api_stdout.txt"),"ab+").write(proc.stdout)
                open(os.path.join(log_path, "cov_api_stderr.txt"),"ab+").write(proc.stderr)
                if os.path.exists(drcov_file):
                    os.system(f'mv {drcov_file} {api_order_iteration_path}/{i}.drcov')
            implemented_apis.append(apis[i])
            i += 1
        os.system(f'rm -rf {out_path}')

def thread_worker(q: queue.Queue):
    while True:
        try:
            job = q.get(block=False)
        except queue.Empty:
            break
        try:
            do_work(job[0], job[1], job[2], job[3])
        finally:
            q.task_done()

def main():
    campaigns = json.load(open("fuzz_config.json"))
    subprocess.run(f'docker kill emu', shell=True)
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
                (os.path.join(tee, "harness", harness), campaigns, tee_api_order, f"{tee}_api_order")
            )
            job_queue.put(
                (os.path.join(tee, "harness", harness), campaigns, all_api_order, "all_api_order")
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
