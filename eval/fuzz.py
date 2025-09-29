import threading
import queue
import os
import time
import subprocess
import sys

BASE = os.path.join(os.path.dirname(__file__), "..")
tees = ["teegris", "mitee", "beanpod", "t6"]
#fuzz_time = 60 * 60 * 24
fuzz_time = 60 * 5

def worker(harness_path):
    print(f"Job {harness_path} starting to fuzz {threading.current_thread().name}")
    print(f'docker exec -e AFL_DEBUG=1 -e TAEMU_CRASH_NOTIMPL=1 -it emu ./fuzz.sh ../{harness_path}')
    subprocess.run(f'docker exec -e FUZZTIME={fuzz_time} -e AFL_DEBUG=1 -e TAEMU_CRASH_NOTIMPL=1 -it emu ./fuzz.sh ../{harness_path}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Job {harness_path} finished fuzzing {threading.current_thread().name}")
    subprocess.run(f'docker exec -e TAEMU_CRASH_NOTIMPL=1 -it emu ./replay.sh ../{harness_path}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Job {harness_path} finished replay {threading.current_thread().name}")
    subprocess.run(f'docker exec -e TAEMU_CRASH_NOTIMPL=1 -it emu ./triage.py ../{harness_path}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Job {harness_path} finished triage {threading.current_thread().name}")

# Worker thread function
def thread_worker(q: queue.Queue):
    while True:
        try:
            job = q.get(block=False)
        except queue.Empty:
            break
        try:
            worker(job)
        finally:
            q.task_done()

def main():
    if 'emu' not in str(subprocess.run('docker ps', shell=True)):
        subprocess.run(f'cd {BASE}  && docker run --rm --name emu --network host -d -v .:/srv -w /srv/emulator -v /dev/shm:/dev/shm --ipc=host --shm-size=100g ta_emu tail -f', shell=True)
    num_cores = os.cpu_count() or 2
    num_threads = max(1, num_cores - 2)  # at least 1 thread
    print(f"Using {num_threads} threads")
    job_queue = queue.Queue()
    for tee in tees:
        for harness in os.listdir(os.path.join(BASE, tee, "harness")):
            job_queue.put(os.path.join(tee, "harness", harness))
            if os.path.exists(f'{BASE}/{tee}/harness/{harness}/out'):
                os.system(f'mv {BASE}/{tee}/harness/{harness}/out {BASE}/{tee}/harness/{harness}/backup_out_{time.time()}')

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=thread_worker, args=(job_queue,))
        t.start()
        threads.append(t)
    job_queue.join()
    for t in threads:
        t.join()

    print("All jobs completed")

if __name__ == "__main__":
    main()

