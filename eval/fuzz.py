# Purpose: Run repeated AFL fuzzing campaigns across configured TEE harnesses,
# replay coverage, preserve campaign outputs, and triage crashes.
# Depends on: Docker image/container ta_emu, emulator/fuzz.sh, replay.sh,
# triage.py, harness directories with ta.txt, TA binaries, and metadata symlinks.
# Input: No CLI arguments; optional TAEMU_FUZZ_TEE restricts the selected TEE.

from pathlib import Path
import threading
import queue
import os
import shutil
import time
import subprocess

BASE = Path(__file__).resolve().parent.parent
CAMPAIGN_DIR = "campaign_out"
FUZZ_CHUNKS = "fuzz_chunk"
COV_DIR = "cov"

TEES = ["teegris", "mitee", "beanpod", "t6"]
FUZZ_TIME = int(os.environ.get("TAEMU_FUZZ_TIME", 60 * 60 * 24))
FUZZ_ITERATIONS = int(os.environ.get("TAEMU_FUZZ_ITERATIONS", 5))


def worker(harness_path):
    harness_path = Path(harness_path)
    harness_dir = BASE / harness_path
    log_path = harness_dir / "logs"
    log_path.mkdir(parents=True, exist_ok=True)
    print(f"Job {harness_path} starting to fuzz {threading.current_thread().name}")
    (log_path / "fuzz_stdout.txt").write_bytes(b"")
    (log_path / "fuzz_stderr.txt").write_bytes(b"")
    (log_path / "replay_stdout.txt").write_bytes(b"")
    (log_path / "replay_stderr.txt").write_bytes(b"")
    fuzz_dir = harness_dir / CAMPAIGN_DIR
    in_path = harness_dir / "in"
    out_path = harness_dir / "out"
    queue_path = out_path / "default" / "queue"
    crashes_path = out_path / "default" / "crashes"
    cov_path = out_path / COV_DIR
    if fuzz_dir.exists():
        shutil.rmtree(fuzz_dir)
    fuzz_dir.mkdir(parents=True)
    for fuzz_iteration in range(0, FUZZ_ITERATIONS):
        if out_path.exists():
            shutil.rmtree(out_path)
        fuzz_iteration_dir = fuzz_dir / f"{fuzz_iteration}"
        fuzz_iteration_dir.mkdir(parents=True)
        if FUZZ_TIME > 60 * 60:
            seed_backup_dir = fuzz_iteration_dir / FUZZ_CHUNKS
            if seed_backup_dir.exists():
                shutil.rmtree(seed_backup_dir)
            seed_backup_dir.mkdir(parents=True)
            for i in range(0, int(FUZZ_TIME / (60 * 60))):
                # ;; avoid memory running out
                print(
                    f"docker exec -e FUZZTIME={60*60} -e AFL_NO_UI=1 -e TAEMU_CRASH_NOTIMPL=1 -it emu ./fuzz.sh ../{harness_path}"
                )
                proc = subprocess.run(
                    f"docker exec -e FUZZTIME={60*60} -e AFL_NO_UI=1 -e TAEMU_CRASH_NOTIMPL=1 -it emu ./fuzz.sh ../{harness_path}",
                    shell=True,
                    capture_output=True,
                )
                with (log_path / "fuzz_stdout.txt").open("ab") as stdout:
                    stdout.write(proc.stdout)
                with (log_path / "fuzz_stderr.txt").open("ab") as stderr:
                    stderr.write(proc.stderr)
                chunk_dir = seed_backup_dir / f"{i}"
                chunk_dir.mkdir(parents=True)
                shutil.copytree(queue_path, chunk_dir / queue_path.name)
                if in_path.exists():
                    shutil.copytree(chunk_dir, in_path / chunk_dir.name)
                else:
                    shutil.copytree(chunk_dir, in_path)
                shutil.copytree(crashes_path, chunk_dir / crashes_path.name)
                print(
                    f"Job {harness_path} finished fuzzing {threading.current_thread().name}"
                )

                proc = subprocess.run(
                    f"docker exec -it emu ./replay.sh ../{harness_path}",
                    shell=True,
                    capture_output=True,
                )
                with (log_path / "replay_stdout.txt").open("ab") as stdout:
                    stdout.write(proc.stdout)
                with (log_path / "replay_stderr.txt").open("ab") as stderr:
                    stderr.write(proc.stderr)
                shutil.move(cov_path, chunk_dir / cov_path.name)
        else:
            print(
                f"docker exec -e FUZZTIME={FUZZ_TIME} -e AFL_NO_UI=1 -e TAEMU_CRASH_NOTIMPL=1 -it emu ./fuzz.sh ../{harness_path}"
            )
            proc = subprocess.run(
                f"timeout {FUZZ_TIME} docker exec -e FUZZTIME={FUZZ_TIME} -e AFL_NO_UI=1 -e TAEMU_CRASH_NOTIMPL=1 -it emu ./fuzz.sh ../{harness_path}",
                shell=True,
                capture_output=True,
            )
            (log_path / "fuzz_stdout.txt").write_bytes(proc.stdout)
            (log_path / "fuzz_stderr.txt").write_bytes(proc.stderr)
            print(
                f"Job {harness_path} finished fuzzing {threading.current_thread().name}"
            )
            proc = subprocess.run(
                f"docker exec -e TAEMU_CRASH_NOTIMPL=1 -it emu ./replay.sh ../{harness_path}",
                shell=True,
                capture_output=True,
            )
            (log_path / "replay_stdout.txt").write_bytes(proc.stdout)
            (log_path / "replay_stderr.txt").write_bytes(proc.stderr)
            shutil.move(cov_path, fuzz_iteration_dir / cov_path.name)
            shutil.copytree(queue_path, fuzz_iteration_dir / queue_path.name)
            shutil.copytree(crashes_path, fuzz_iteration_dir / crashes_path.name)

        if in_path.exists():
            shutil.rmtree(in_path)

    for fuzz_iteration in range(0, FUZZ_ITERATIONS):
        fuzz_iteration_dir = fuzz_dir / f"{fuzz_iteration}"
        if FUZZ_TIME > 60 * 60:
            seed_backup_dir = fuzz_iteration_dir / FUZZ_CHUNKS
            for index in seed_backup_dir.iterdir():
                for crash in (index / "crashes").iterdir():
                    shutil.copy2(crash, crashes_path)
        else:
            for crash in (fuzz_iteration_dir / "crashes").iterdir():
                shutil.copy2(crash, crashes_path)

    print(f"Job {harness_path} finished replay {threading.current_thread().name}")
    proc = subprocess.run(
        f"docker exec -e TAEMU_CRASH_NOTIMPL=1 -it emu ./triage.py ../{harness_path}",
        shell=True,
        capture_output=True,
    )
    (log_path / "triage_stdout.txt").write_bytes(proc.stdout)
    (log_path / "triage_stderr.txt").write_bytes(proc.stderr)
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
    if "TAEMU_FUZZ_TEE" in os.environ:
        tees = [os.environ["TAEMU_FUZZ_TEE"]]
    else:
        tees = TEES
    subprocess.run("docker kill emu", shell=True)
    if "emu" not in str(subprocess.run("docker ps", shell=True)):
        subprocess.run(
            f"cd {BASE}  && docker run --rm --name emu --network host -d -v .:/srv -w /srv/emulator -v /dev/shm:/dev/shm --ipc=host --shm-size=100g ta_emu tail -f",
            shell=True,
        )
    num_cores = os.cpu_count() or 2
    num_threads = max(1, num_cores - 5)  # at least 1 thread
    print(f"Using {num_threads} threads")
    job_queue = queue.Queue()
    now_time = time.time()
    for tee in tees:
        harness_root = BASE / tee / "harness"
        for harness_dir in harness_root.iterdir():
            if harness_dir.name == "__pycache__":
                continue
            if not harness_dir.is_dir():
                print("Harness is not a dir")
                continue
            # if not (harness_dir / "ta.txt").exists():
            #     print(f"!!!!!! {harness_dir} has no ta.txt!!!!!")
            #     exit(-1)
            if (harness_dir / "IGNOREME").exists():
                continue
            if (harness_dir / "IGNORE").exists():
                continue
            # ta_name = (
            #     (harness_dir / "ta.txt")
            #     .read_text()
            #     .strip("\n")
            # )
            # if not (harness_dir / ta_name).exists():
            #     os.symlink(
            #         Path("..", "..", "tas", ta_name),
            #         Path("..", tee, "harness", harness_dir.name, ta_name),
            #     )
            #     os.symlink(
            #         Path("..", "..", "tas", Path(ta_name).with_suffix(".json")),
            #         Path(
            #             "..",
            #             tee,
            #             "harness",
            #             harness_dir.name,
            #             Path(ta_name).with_suffix(".json"),
            #         ),
            #     )
            job_queue.put(Path(tee) / "harness" / harness_dir.name)
            out_dir = harness_dir / "out"
            if out_dir.exists():
                shutil.move(out_dir, harness_dir / f"backup_out_{now_time}")
            triage_dir = harness_dir / "triage"
            if triage_dir.exists():
                shutil.move(triage_dir, harness_dir / f"backup_triage_{now_time}")
            notimpl_dir = harness_dir / "notimpl"
            if notimpl_dir.exists():
                shutil.move(notimpl_dir, harness_dir / f"backup_notimpl_{now_time}")

    threads = []
    for _ in range(num_threads):
        now_time = threading.Thread(target=thread_worker, args=(job_queue,))
        now_time.start()
        time.sleep(1)
        threads.append(now_time)
    job_queue.join()
    for now_time in threads:
        now_time.join()

    print("All jobs completed")


if __name__ == "__main__":
    main()
