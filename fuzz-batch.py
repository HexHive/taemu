#!/usr/bin/env python3
"""Foreground batch scheduler for TA emulator fuzzing campaigns."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_TRIAGE_HOOK = "/srv/medic/auto-triage.sh"
DEFAULT_CONTAINER_PREFIX = "taemu-batch-fuzz-"
DEFAULT_IMAGE = "ta_emu"
DEFAULT_MEMORY = "8g"
DEFAULT_REPEAT = 5
DEFAULT_FUZZTIME = 86400
DEFAULT_FUZZTIME_GRACE = 60
DEFAULT_SHM_SIZE = "100g"
STOP_REQUEST_FILE = "STOP_REQUESTED"
STATE_ORDER = ("planned", "running", "done", "timed_out", "failed", "interrupted")


class BatchError(Exception):
    """User-facing batch scheduler error."""


@dataclass(frozen=True)
class Harness:
    path: Path
    relpath: Path
    name: str
    ta: Path
    config: Path
    input_dir: Path | None


@dataclass
class Job:
    job_id: str
    harness: Harness
    repeat_index: int
    job_dir: Path
    in_dir: Path
    out_dir: Path
    logs_dir: Path
    triage_dir: Path
    meta_dir: Path
    state: str = "planned"
    cpu: str | None = None
    slot: int | None = None
    container_name: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    exit_status: int | None = None
    log_path: Path | None = None


@dataclass
class ActiveJob:
    job: Job
    process: subprocess.Popen[Any]
    log_file: Any


@dataclass
class Scheduler:
    args: argparse.Namespace
    cpus: list[str]
    run_dir: Path
    status_dir: Path
    jobs: list[Job]
    stop_requested: bool = False
    active: dict[int, ActiveJob] = field(default_factory=dict)
    completed_recent: list[Job] = field(default_factory=list)
    start_monotonic: float = field(default_factory=time.monotonic)
    last_render_lines: int = 0
    last_plain_log: float = 0.0

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_requested = True

    def run(self) -> int:
        old_int = signal.getsignal(signal.SIGINT)
        old_term = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)
        exit_code = 0
        try:
            self._write_initial_state()
            self._render(force=True)
            pending = list(self.jobs)
            while pending or self.active:
                self._poll_external_stop()
                if self.stop_requested:
                    exit_code = 130
                    self._interrupt_active()
                    for job in pending:
                        job.state = "interrupted"
                        job.finished_at = now_iso()
                        write_job_state(self.status_dir, job)
                    pending.clear()
                else:
                    self._reap_finished()
                    while pending and len(self.active) < self.args.slots:
                        slot = self._next_free_slot()
                        job = pending.pop(0)
                        self._start_job(slot, job)
                self._render()
                if self.active:
                    time.sleep(0.5)
            self._render(force=True, final=True)
            if any(job.state in {"failed", "interrupted"} for job in self.jobs):
                exit_code = exit_code or 1
            return exit_code
        finally:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)
            for active in list(self.active.values()):
                active.log_file.close()

    def _write_initial_state(self) -> None:
        for job in self.jobs:
            write_job_state(self.status_dir, job)

    def _poll_external_stop(self) -> None:
        if (self.run_dir / STOP_REQUEST_FILE).exists():
            self.stop_requested = True

    def _next_free_slot(self) -> int:
        for slot in range(self.args.slots):
            if slot not in self.active:
                return slot
        raise RuntimeError("no free slot")

    def _start_job(self, slot: int, job: Job) -> None:
        cpu = self.cpus[slot]
        job.cpu = cpu
        job.slot = slot
        job.state = "running"
        job.started_at = now_iso()
        job.container_name = make_container_name(self.args.container_prefix, job.job_id)
        job.log_path = job.logs_dir / "docker.log"
        job.logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = job.log_path.open("ab")
        cmd = build_docker_command(self.args, self.run_dir, job, cpu)
        append_scheduler_log(self.run_dir, f"starting {job.job_id} slot={slot} cpu={cpu}: {quote_cmd(cmd)}")
        write_job_state(self.status_dir, job)
        try:
            process = subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=log_file, stderr=subprocess.STDOUT)
        except Exception:
            log_file.close()
            job.state = "failed"
            job.finished_at = now_iso()
            job.exit_status = 127
            write_job_state(self.status_dir, job)
            raise
        self.active[slot] = ActiveJob(job=job, process=process, log_file=log_file)

    def _reap_finished(self) -> None:
        for slot, active in list(self.active.items()):
            rc = active.process.poll()
            if rc is None:
                update_crash_stats(active.job)
                write_job_state(self.status_dir, active.job)
                continue
            active.log_file.close()
            job = active.job
            job.exit_status = rc
            job.finished_at = now_iso()
            job.state = classify_exit_state(job, rc, self.args.fuzztime)
            update_crash_stats(job)
            write_job_state(self.status_dir, job)
            append_scheduler_log(self.run_dir, f"finished {job.job_id} state={job.state} exit_status={rc}")
            self.completed_recent.append(job)
            self.completed_recent = self.completed_recent[-5:]
            del self.active[slot]

    def _interrupt_active(self) -> None:
        for active in list(self.active.values()):
            job = active.job
            if job.container_name:
                docker_stop(job.container_name)
            if active.process.poll() is None:
                active.process.terminate()
        deadline = time.monotonic() + 10
        while self.active and time.monotonic() < deadline:
            self._reap_finished()
            time.sleep(0.2)
        for slot, active in list(self.active.items()):
            if active.process.poll() is None:
                active.process.kill()
            active.log_file.close()
            job = active.job
            job.state = "interrupted"
            job.finished_at = now_iso()
            job.exit_status = active.process.poll()
            write_job_state(self.status_dir, job)
            del self.active[slot]

    def _render(self, force: bool = False, final: bool = False) -> None:
        if sys.stdout.isatty():
            lines = render_dashboard(self.run_dir, self.jobs, self.active, self.completed_recent, self.start_monotonic, final)
            text = "\n".join(lines)
            if self.last_render_lines:
                sys.stdout.write(f"\x1b[{self.last_render_lines}F")
            sys.stdout.write(text)
            sys.stdout.write("\n")
            if self.last_render_lines > len(lines):
                for _ in range(self.last_render_lines - len(lines)):
                    sys.stdout.write("\x1b[2K\n")
            sys.stdout.flush()
            self.last_render_lines = len(lines)
            return

        now = time.monotonic()
        if force or final or now - self.last_plain_log >= 30:
            self.last_plain_log = now
            counts = state_counts(self.jobs)
            print(
                f"[{now_iso()}] elapsed={format_duration(int(now - self.start_monotonic))} "
                f"planned={counts['planned']} running={counts['running']} done={counts['done']} "
                f"timed_out={counts['timed_out']} failed={counts['failed']} interrupted={counts['interrupted']}",
                flush=True,
            )


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_cpu_list(raw: str) -> list[str]:
    if not raw:
        raise BatchError("--cpus must not be empty")
    cpus: list[int] = []
    seen: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            raise BatchError(f"invalid CPU list: {raw}")
        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise BatchError(f"invalid CPU range: {part}")
            start, end = int(bounds[0]), int(bounds[1])
            if start > end:
                raise BatchError(f"invalid descending CPU range: {part}")
            values = range(start, end + 1)
        else:
            if not part.isdigit():
                raise BatchError(f"invalid CPU value: {part}")
            values = [int(part)]
        for value in values:
            if value in seen:
                raise BatchError(f"duplicate CPU in --cpus: {value}")
            seen.add(value)
            cpus.append(value)
    return [str(cpu) for cpu in cpus]


def safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip())
    return cleaned.strip("-") or "job"


def make_container_name(prefix: str, job_id: str) -> str:
    name = safe_name(prefix + job_id)
    return name[:120]


def quote_cmd(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


def repo_relative(path: Path) -> Path:
    try:
        return path.resolve().relative_to(REPO_ROOT)
    except ValueError as exc:
        raise BatchError(f"harness must be inside repo root {REPO_ROOT}: {path}") from exc


def load_harness_paths(args: argparse.Namespace) -> list[Path]:
    modes = sum(bool(x) for x in (args.harness_root, args.manifest, args.harnesses))
    if modes != 1:
        raise BatchError("specify exactly one input mode: -d, --manifest, or explicit harness directories")

    if args.harness_root:
        root = Path(args.harness_root).resolve()
        if not root.is_dir():
            raise BatchError(f"harness root not found: {root}")
        return sorted(path.resolve() for path in root.iterdir() if path.is_dir())

    if args.manifest:
        manifest = Path(args.manifest).resolve()
        if not manifest.is_file():
            raise BatchError(f"manifest not found: {manifest}")
        paths = []
        for line_no, raw in enumerate(manifest.read_text().splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            path = Path(line)
            if not path.is_absolute():
                path = manifest.parent / path
            paths.append(path.resolve())
        if not paths:
            raise BatchError(f"manifest contains no harness paths: {manifest}")
        return paths

    return [Path(path).resolve() for path in args.harnesses]


def validate_harness(path: Path) -> Harness:
    if not path.is_dir():
        raise BatchError(f"harness directory not found: {path}")
    relpath = repo_relative(path)
    if not (path / "harness.py").is_file():
        raise BatchError(f"missing harness.py: {path}")

    tas = sorted(list(path.glob("*.ta")) + list(path.glob("*.elf")))
    if not tas:
        raise BatchError(f"missing .ta or .elf target: {path}")
    ta = tas[0]
    config_candidates = [ta.with_suffix(".yml"), ta.with_suffix(".json")]
    config = next((candidate for candidate in config_candidates if candidate.is_file()), None)
    if config is None:
        raise BatchError(f"missing config next to {ta.name}: expected {config_candidates[0].name} or {config_candidates[1].name}")

    input_dir = path / "in"
    return Harness(
        path=path,
        relpath=relpath,
        name=path.name,
        ta=ta,
        config=config,
        input_dir=input_dir if input_dir.is_dir() else None,
    )


def validate_preflight(args: argparse.Namespace) -> tuple[list[str], list[Harness]]:
    run_dir = Path(args.run_dir).resolve()
    if run_dir.exists():
        raise BatchError(f"run-dir already exists: {run_dir}")

    cpus = parse_cpu_list(args.cpus)
    if args.slots is None:
        args.slots = len(cpus)
    if args.slots < 1:
        raise BatchError("--slots must be at least 1")
    if args.slots > len(cpus):
        raise BatchError("--slots must be less than or equal to the number of configured CPUs")
    if args.repeat < 1:
        raise BatchError("--repeat must be at least 1")
    if args.fuzztime < 1:
        raise BatchError("--fuzztime must be at least 1")
    if args.fuzztime_grace < 1:
        raise BatchError("--fuzztime-grace must be at least 1")
    if not args.memory:
        raise BatchError("--memory must not be empty")

    ntfy_token = os.environ.get("NTFY_TOKEN")
    ntfy_topic = os.environ.get("NTFY_TOPIC")
    if bool(ntfy_token) != bool(ntfy_topic):
        raise BatchError("NTFY_TOKEN and NTFY_TOPIC must be both set or both unset")

    if shutil.which("docker") is None:
        raise BatchError("docker is not available on PATH")
    harnesses = [validate_harness(path) for path in load_harness_paths(args)]
    if not harnesses:
        raise BatchError("no harness directories found")
    return cpus, harnesses


def create_run_layout(run_dir: Path) -> None:
    (run_dir / "status").mkdir(parents=True)
    (run_dir / "reports").mkdir()
    (run_dir / "jobs").mkdir()


def copy_or_seed_corpus(harness: Harness, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    if harness.input_dir is not None:
        shutil.copytree(harness.input_dir, dst, dirs_exist_ok=True)
    if any(dst.iterdir()):
        return
    (dst / "foo").write_bytes(b"foo\n")
    (dst / "foo2").write_bytes(b"\x00")
    (dst / "foo3").write_bytes(b"\x00\x00")
    (dst / "foo4").write_bytes(b"\x00" * 4)
    (dst / "foo5").write_bytes(b"\x00" * 8)


def generate_jobs(run_dir: Path, harnesses: list[Harness], repeat: int) -> list[Job]:
    jobs: list[Job] = []
    used_ids: set[str] = set()
    for harness in harnesses:
        base = safe_name(harness.name)
        for repeat_index in range(1, repeat + 1):
            job_id = f"{base}-r{repeat_index:03d}"
            if job_id in used_ids:
                job_id = f"{safe_name(str(harness.relpath))}-r{repeat_index:03d}"
            used_ids.add(job_id)
            job_dir = run_dir / "jobs" / job_id
            jobs.append(
                Job(
                    job_id=job_id,
                    harness=harness,
                    repeat_index=repeat_index,
                    job_dir=job_dir,
                    in_dir=job_dir / "in",
                    out_dir=job_dir / "out",
                    logs_dir=job_dir / "logs",
                    triage_dir=job_dir / "triage",
                    meta_dir=job_dir / "meta",
                )
            )
    return jobs


def materialize_jobs(jobs: list[Job]) -> None:
    for job in jobs:
        job.meta_dir.mkdir(parents=True, exist_ok=True)
        job.out_dir.mkdir(parents=True, exist_ok=True)
        job.logs_dir.mkdir(parents=True, exist_ok=True)
        job.triage_dir.mkdir(parents=True, exist_ok=True)
        copy_or_seed_corpus(job.harness, job.in_dir)


def write_campaign_files(args: argparse.Namespace, cpus: list[str], harnesses: list[Harness], jobs: list[Job]) -> None:
    run_dir = Path(args.run_dir).resolve()
    campaign = {
        "created_at": now_iso(),
        "repo_root": str(REPO_ROOT),
        "raw_args": sys.argv,
        "image": args.image,
        "cpus": cpus,
        "slots": args.slots,
        "repeat": args.repeat,
        "fuzztime": args.fuzztime,
        "fuzztime_grace": args.fuzztime_grace,
        "fuzz_timeout": args.fuzz_timeout,
        "memory": args.memory,
        "container_prefix": args.container_prefix,
        "triage_hook": args.triage_hook,
        "env": relevant_env(),
    }
    write_json_atomic(run_dir / "campaign.json", campaign)

    with (run_dir / "harnesses.tsv").open("w", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t")
        writer.writerow(["index", "name", "relpath", "ta", "config", "input_dir"])
        for index, harness in enumerate(harnesses, start=1):
            writer.writerow([index, harness.name, harness.relpath, harness.ta.name, harness.config.name, harness.input_dir or ""])

    with (run_dir / "jobs.tsv").open("w", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t")
        writer.writerow(["job_id", "harness", "harness_relpath", "repeat_index", "job_dir"])
        for job in jobs:
            writer.writerow([job.job_id, job.harness.name, job.harness.relpath, job.repeat_index, job.job_dir])


def relevant_env() -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in os.environ.items():
        if key.startswith("AFL_") or key in {"FUZZTIME", "FUZZTIME_GRACE", "FUZZ_TIMEOUT", "NTFY_TOKEN", "NTFY_TOPIC", "NTFY_URL"}:
            out[key] = "<set>" if "TOKEN" in key else value
    return out


def append_scheduler_log(run_dir: Path, message: str) -> None:
    with (run_dir / "scheduler.log").open("a") as fh:
        fh.write(f"[{now_iso()}] {message}\n")


def job_to_state(job: Job) -> dict[str, Any]:
    crash_stats = get_crash_stats(job)
    return {
        "job_id": job.job_id,
        "state": job.state,
        "harness": job.harness.name,
        "harness_relpath": str(job.harness.relpath),
        "repeat_index": job.repeat_index,
        "slot": job.slot,
        "cpu": job.cpu,
        "container_name": job.container_name,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "exit_status": job.exit_status,
        "job_dir": str(job.job_dir),
        "in_dir": str(job.in_dir),
        "out_dir": str(job.out_dir),
        "triage_dir": str(job.triage_dir),
        "log_path": str(job.log_path) if job.log_path else None,
        "crash_count": crash_stats["crash_count"],
        "latest_crash": crash_stats["latest_crash"],
    }


def write_job_state(status_dir: Path, job: Job) -> None:
    write_json_atomic(status_dir / f"{job.job_id}.json", job_to_state(job))


def write_json_atomic(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def get_crash_stats(job: Job) -> dict[str, Any]:
    crash_root = job.out_dir / "default"
    candidates = [crash_root / "crashes"]
    candidates.extend(sorted(crash_root.glob("crashes.*")))
    crashes: list[Path] = []
    for crash_dir in candidates:
        if not crash_dir.is_dir():
            continue
        for item in crash_dir.iterdir():
            if item.is_file() and item.name != "README.txt":
                crashes.append(item)
    latest = max(crashes, key=lambda path: path.stat().st_mtime, default=None)
    return {"crash_count": len(crashes), "latest_crash": str(latest) if latest else None}


def update_crash_stats(_job: Job) -> None:
    # Crash stats are computed from disk when state is written.
    return


def build_docker_command(args: argparse.Namespace, run_dir: Path, job: Job, cpu: str) -> list[str]:
    container_harness = f"/srv/{job.harness.relpath.as_posix()}"
    container_job_dir = f"/campaign/jobs/{job.job_id}"
    fuzz_cmd = [
        "/srv/emulator/fuzz.sh",
        container_harness,
        "--in_dir",
        f"{container_job_dir}/in",
        "--out_dir",
        f"{container_job_dir}/out",
        "--triage_report_dir",
        f"{container_job_dir}/triage",
        "-I",
        args.triage_hook,
    ]
    notify_cmd = [
        "/srv/medic/ntfy-hook.sh",
        "afl-stopped",
        container_harness,
        f"{container_job_dir}/out",
    ]
    shell = (
        "set -u; "
        f"{quote_cmd(fuzz_cmd)}; "
        "status=$?; "
        f"{quote_cmd(notify_cmd)} \"exit_status=$status\"; "
        "exit $status"
    )

    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        job.container_name or make_container_name(args.container_prefix, job.job_id),
        "--cpuset-cpus",
        cpu,
        "--ulimit",
        "core=0",
        "--memory",
        args.memory,
        "--memory-swap",
        args.memory,
        "--network",
        "host",
        "--volume",
        f"{REPO_ROOT}:/srv",
        "--volume",
        f"{run_dir}:/campaign",
        "--workdir",
        "/srv/emulator",
        "--shm-size",
        DEFAULT_SHM_SIZE,
        "--ipc",
        "host",
        "--user",
        "root",
    ]

    env = docker_env(args)
    for key, value in env.items():
        cmd.extend(["-e", f"{key}={value}"])

    cmd.extend([args.image, "bash", "-lc", shell])
    return cmd


def docker_env(args: argparse.Namespace) -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key.startswith("AFL_"):
            env[key] = value
    env["AFL_NO_AFFINITY"] = "1"
    env["TAEMU_CRASH_NOTIMPL"] = "1"
    env["FUZZTIME"] = str(args.fuzztime)
    env["FUZZTIME_GRACE"] = str(args.fuzztime_grace)
    if args.fuzz_timeout:
        env["FUZZ_TIMEOUT"] = str(args.fuzz_timeout)
    elif os.environ.get("FUZZ_TIMEOUT"):
        env["FUZZ_TIMEOUT"] = os.environ["FUZZ_TIMEOUT"]
    for key in ("NTFY_TOKEN", "NTFY_TOPIC", "NTFY_URL"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def docker_stop(container_name: str) -> None:
    subprocess.run(["docker", "stop", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def read_states(run_dir: Path) -> list[dict[str, Any]]:
    status_dir = run_dir / "status"
    if not status_dir.is_dir():
        raise BatchError(f"status directory not found: {status_dir}")
    states = []
    for path in sorted(status_dir.glob("*.json")):
        try:
            states.append(json.loads(path.read_text()))
        except json.JSONDecodeError as exc:
            raise BatchError(f"invalid state file: {path}") from exc
    return states


def state_counts_from_states(states: list[dict[str, Any]]) -> dict[str, int]:
    counts = {state: 0 for state in STATE_ORDER}
    for state in states:
        counts[state.get("state", "failed")] = counts.get(state.get("state", "failed"), 0) + 1
    return counts


def state_counts(jobs: list[Job]) -> dict[str, int]:
    counts = {state: 0 for state in STATE_ORDER}
    for job in jobs:
        counts[job.state] = counts.get(job.state, 0) + 1
    return counts


def render_dashboard(
    run_dir: Path,
    jobs: list[Job],
    active: dict[int, ActiveJob],
    recent: list[Job],
    start_monotonic: float,
    final: bool,
) -> list[str]:
    term_width = shutil.get_terminal_size((120, 30)).columns
    counts = state_counts(jobs)
    elapsed = format_duration(int(time.monotonic() - start_monotonic))
    title_state = "complete" if final else "running"
    lines = [
        trim(f"TAEMU fuzz batch [{title_state}]  elapsed={elapsed}  run_dir={run_dir}", term_width),
        trim(
            f"planned={counts['planned']} running={counts['running']} done={counts['done']} "
            f"timed_out={counts['timed_out']} failed={counts['failed']} interrupted={counts['interrupted']}",
            term_width,
        ),
        "slot cpu     state        runtime   crashes job                         harness",
    ]
    for slot in sorted(active):
        job = active[slot].job
        stats = get_crash_stats(job)
        runtime = runtime_for(job)
        lines.append(
            trim(
                f"{slot:<4} {str(job.cpu or ''):<7} {job.state:<12} {runtime:<9} "
                f"{stats['crash_count']:<7} {job.job_id:<27} {job.harness.name}",
                term_width,
            )
        )
    if not active:
        lines.append("no active jobs")
    if recent:
        lines.append("recent:")
        for job in reversed(recent[-5:]):
            lines.append(trim(f"  {job.state:<11} exit={job.exit_status!s:<4} {job.job_id} {job.harness.name}", term_width))
    lines.append(trim(f"logs: {run_dir / 'scheduler.log'} and {run_dir / 'jobs' / '<job_id>' / 'logs'}", term_width))
    return [f"\x1b[2K{line}" for line in lines]


def trim(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.fromisoformat(raw)


def runtime_for(job: Job) -> str:
    start = parse_iso(job.started_at)
    if not start:
        return "-"
    end = parse_iso(job.finished_at) or datetime.now(timezone.utc)
    return format_duration(max(0, int((end - start).total_seconds())))


def runtime_seconds(job: Job) -> int:
    start = parse_iso(job.started_at)
    if not start:
        return 0
    end = parse_iso(job.finished_at) or datetime.now(timezone.utc)
    return max(0, int((end - start).total_seconds()))


def classify_exit_state(job: Job, exit_status: int, fuzztime: int) -> str:
    reached_fuzztime = runtime_seconds(job) >= max(0, fuzztime - 5)
    if exit_status in {0, 124} and reached_fuzztime:
        return "timed_out"
    if exit_status == 0:
        return "done"
    return "failed"


def format_duration(seconds: int) -> str:
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def cmd_start(args: argparse.Namespace) -> int:
    cpus, harnesses = validate_preflight(args)
    run_dir = Path(args.run_dir).resolve()
    jobs = generate_jobs(run_dir, harnesses, args.repeat)

    if args.dry_run:
        print(f"dry-run ok: {len(harnesses)} harnesses, {len(jobs)} jobs, slots={args.slots}, cpus={','.join(cpus)}")
        for job in jobs:
            print(f"{job.job_id}\t{job.harness.relpath}\trepeat={job.repeat_index}")
        return 0

    create_run_layout(run_dir)
    materialize_jobs(jobs)
    write_campaign_files(args, cpus, harnesses, jobs)
    append_scheduler_log(run_dir, f"created campaign jobs={len(jobs)} slots={args.slots} cpus={','.join(cpus)}")
    scheduler = Scheduler(args=args, cpus=cpus, run_dir=run_dir, status_dir=run_dir / "status", jobs=jobs)
    return scheduler.run()


def cmd_status(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    states = read_states(run_dir)
    counts = state_counts_from_states(states)
    active = [state for state in states if state.get("state") == "running"]
    failures = [state for state in states if state.get("state") in {"failed", "interrupted"}]

    summary = {
        "run_dir": str(run_dir),
        "totals": counts,
        "active": active,
        "failures": failures[-10:],
        "jobs": states,
    }
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f"run_dir: {run_dir}")
    print(
        f"planned={counts['planned']} running={counts['running']} done={counts['done']} "
        f"timed_out={counts['timed_out']} failed={counts['failed']} interrupted={counts['interrupted']}"
    )
    if active:
        print("active:")
        for state in active:
            print(
                f"  slot={state.get('slot')} cpu={state.get('cpu')} job={state.get('job_id')} "
                f"harness={state.get('harness')} crashes={state.get('crash_count')} latest={state.get('latest_crash')}"
            )
    if failures:
        print("recent failures:")
        for state in failures[-10:]:
            print(f"  {state.get('state')} exit={state.get('exit_status')} job={state.get('job_id')} log={state.get('log_path')}")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    states = read_states(run_dir)
    (run_dir / STOP_REQUEST_FILE).write_text(f"{now_iso()}\n")
    active = [state for state in states if state.get("state") == "running" and state.get("container_name")]
    if not active:
        print("no running containers recorded")
        return 0
    for state in active:
        container = state["container_name"]
        print(f"stopping {container} ({state.get('job_id')})")
        docker_stop(container)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run fixed-slot Docker fuzzing batches.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="start a foreground batch campaign")
    start.add_argument("harnesses", nargs="*", help="explicit harness directories")
    start.add_argument("-d", dest="harness_root", help="discover harnesses one level below this directory")
    start.add_argument("--manifest", help="read harness paths, one per non-empty non-comment line")
    start.add_argument("--run-dir", required=True, help="central campaign directory; must not already exist")
    start.add_argument("--cpus", required=True, help="explicit Docker cpuset CPU list, e.g. 10-54 or 10,12,14")
    start.add_argument("--slots", type=int, help="max concurrent jobs; default is number of CPUs in --cpus")
    start.add_argument("--repeat", type=int, default=DEFAULT_REPEAT, help=f"repeat each harness; default {DEFAULT_REPEAT}")
    start.add_argument("--fuzztime", type=int, default=DEFAULT_FUZZTIME, help=f"per-job AFL runtime; default {DEFAULT_FUZZTIME}")
    start.add_argument(
        "--fuzztime-grace",
        type=int,
        default=DEFAULT_FUZZTIME_GRACE,
        help=f"outer timeout grace seconds after AFL -V; default {DEFAULT_FUZZTIME_GRACE}",
    )
    start.add_argument("--fuzz-timeout", dest="fuzz_timeout", type=int, help="forwarded as FUZZ_TIMEOUT if set")
    start.add_argument("--image", default=DEFAULT_IMAGE, help=f"Docker image; default {DEFAULT_IMAGE}")
    start.add_argument("--memory", default=DEFAULT_MEMORY, help=f"Docker memory and memory-swap limit; default {DEFAULT_MEMORY}")
    start.add_argument("--container-prefix", default=DEFAULT_CONTAINER_PREFIX, help=f"default {DEFAULT_CONTAINER_PREFIX}")
    start.add_argument("--triage-hook", default=DEFAULT_TRIAGE_HOOK, help=f"default {DEFAULT_TRIAGE_HOOK}")
    start.add_argument("--dry-run", action="store_true", help="run preflight and print planned jobs without starting")
    start.set_defaults(func=cmd_start)

    status = subparsers.add_parser("status", help="show campaign status")
    status.add_argument("--run-dir", required=True)
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    stop = subparsers.add_parser("stop", help="stop running containers recorded in a campaign")
    stop.add_argument("--run-dir", required=True)
    stop.set_defaults(func=cmd_stop)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
