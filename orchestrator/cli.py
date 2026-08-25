#!/usr/bin/env python3
"""Foreground batch scheduler for TA emulator fuzzing campaigns."""

from __future__ import annotations

import argparse
import csv
import fnmatch
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

from .model import (
    DEFAULT_CONTAINER_PREFIX,
    DEFAULT_FUZZTIME,
    DEFAULT_FUZZTIME_GRACE,
    DEFAULT_IMAGE,
    DEFAULT_MEMORY,
    DEFAULT_REPEAT,
    DEFAULT_REPLAY_TIMEOUT,
    DEFAULT_SHM_SIZE,
    DEFAULT_TRIAGE_HOOK,
    SECRET_ENV_KEYS,
    STATE_ORDER,
    STOP_REQUEST_FILE,
    TRIAGE_RESULT_TYPES,
    ActiveJob,
    BatchError,
    Harness,
    Job,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


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
    tmux_session_created: bool = False

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_requested = True

    def run(self) -> int:
        old_int = signal.getsignal(signal.SIGINT)
        old_term = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)
        exit_code = 0
        try:
            if self.args.tmux_session:
                self._prepare_tmux_session()
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
                if active.log_file:
                    active.log_file.close()

    def _write_initial_state(self) -> None:
        for job in self.jobs:
            write_job_state(self.status_dir, job)
        self._verbose(
            f"initialized {len(self.jobs)} job state files in {self.status_dir}; "
            f"STOP file: {self.run_dir / STOP_REQUEST_FILE}"
        )

    def _poll_external_stop(self) -> None:
        if (self.run_dir / STOP_REQUEST_FILE).exists():
            self.stop_requested = True

    def _next_free_slot(self) -> int:
        for slot in range(self.args.slots):
            if slot not in self.active:
                return slot
        raise RuntimeError("no free slot")

    def _prepare_tmux_session(self) -> None:
        if shutil.which("tmux") is None:
            raise BatchError("tmux is not available on PATH")
        existing = subprocess.run(
            ["tmux", "has-session", "-t", self.args.tmux_session],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if existing.returncode == 0:
            raise BatchError(f"tmux session already exists: {self.args.tmux_session}")

    def _start_job(self, slot: int, job: Job) -> None:
        cpu = self.cpus[slot]
        job.cpu = cpu
        job.slot = slot
        job.state = "running"
        job.started_at = now_iso()
        job.container_name = make_container_name(self.args.container_prefix, job.job_id)
        job.log_path = job.logs_dir / "docker.log"
        job.logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = None if self.args.tmux_session else job.log_path.open("ab")
        cmd = build_docker_command(self.args, self.run_dir, job, cpu, interactive=bool(self.args.tmux_session))
        append_scheduler_log(self.run_dir, f"starting {job.job_id} slot={slot} cpu={cpu}: {quote_redacted_cmd(cmd)}")
        self._verbose(
            f"start job={job.job_id} harness={job.harness.name} slot={slot} cpu={cpu} "
            f"container={job.container_name} out={job.out_dir} log={job.log_path}"
        )
        if self.args.tmux_session:
            self._verbose(f"tmux target session={self.args.tmux_session} window={safe_name(job.job_id)[:80]}")
        else:
            self._verbose(f"docker argv: {quote_redacted_cmd(cmd)}")
        append_event(
            self.run_dir,
            "job_start",
            job_id=job.job_id,
            slot=slot,
            cpu=cpu,
            container_name=job.container_name,
            argv=redact_cmd(cmd),
        )
        write_job_state(self.status_dir, job)
        try:
            if self.args.tmux_session:
                self._start_tmux_window(job, cmd)
                process = None
            else:
                process = subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=log_file, stderr=subprocess.STDOUT)
        except Exception:
            if log_file:
                log_file.close()
            job.state = "failed"
            job.finished_at = now_iso()
            job.exit_status = 127
            write_job_state(self.status_dir, job)
            raise
        self.active[slot] = ActiveJob(job=job, process=process, log_file=log_file)

    def _start_tmux_window(self, job: Job, cmd: list[str]) -> None:
        exit_marker = job.meta_dir / "exit_status"
        window_name = safe_name(job.job_id)[:80]
        shell = (
            "set -u; "
            f"{quote_cmd(cmd)}; "
            "status=$?; "
            f"printf '%s\\n' \"$status\" > {shlex.quote(str(exit_marker))}; "
            "echo; "
            f"echo 'job {shlex.quote(job.job_id)} exited with status '\"$status\"; "
            "exec bash -i"
        )
        if not self.tmux_session_created:
            tmux_cmd = [
                "tmux",
                "new-session",
                "-d",
                "-P",
                "-F",
                "#{pane_id}",
                "-s",
                self.args.tmux_session,
                "-n",
                window_name,
                "-c",
                str(REPO_ROOT),
                shell,
            ]
        else:
            tmux_cmd = [
                "tmux",
                "new-window",
                "-P",
                "-F",
                "#{pane_id}",
                "-t",
                self.args.tmux_session,
                "-n",
                window_name,
                "-c",
                str(REPO_ROOT),
                shell,
            ]
        created = subprocess.run(tmux_cmd, check=True, capture_output=True, text=True)
        tmux_pane = created.stdout.strip()
        if not tmux_pane:
            raise BatchError(f"tmux did not report a pane id for job {job.job_id}")
        if not self.tmux_session_created:
            self.tmux_session_created = True
        if job.log_path:
            pipe_cmd = f"cat >> {shlex.quote(str(job.log_path))}"
            subprocess.run(["tmux", "pipe-pane", "-o", "-t", tmux_pane, pipe_cmd], check=False)
        self._verbose(
            f"tmux window ready: session={self.args.tmux_session} window={window_name} pane={tmux_pane}; "
            f"attach with: tmux attach -t {self.args.tmux_session}"
        )

    def _poll_tmux_job(self, job: Job) -> int | None:
        exit_marker = job.meta_dir / "exit_status"
        if not exit_marker.is_file():
            return None
        try:
            return int(exit_marker.read_text().strip())
        except (OSError, ValueError):
            return 127

    def _reap_finished(self) -> None:
        for slot, active in list(self.active.items()):
            rc = self._poll_tmux_job(active.job) if active.process is None else active.process.poll()
            if rc is None:
                update_crash_stats(active.job)
                write_job_state(self.status_dir, active.job)
                continue
            if active.log_file:
                active.log_file.close()
            job = active.job
            job.exit_status = rc
            job.finished_at = now_iso()
            job.state = classify_exit_state(job, rc, self.args.fuzztime)
            update_crash_stats(job)
            write_job_state(self.status_dir, job)
            append_scheduler_log(self.run_dir, f"finished {job.job_id} state={job.state} exit_status={rc}")
            append_event(self.run_dir, "job_finish", job_id=job.job_id, state=job.state, exit_status=rc)
            self._verbose(
                f"finish job={job.job_id} state={job.state} exit={rc} "
                f"runtime={runtime_for(job)} out={job.out_dir} log={job.log_path}"
            )
            self.completed_recent.append(job)
            self.completed_recent = self.completed_recent[-5:]
            del self.active[slot]

    def _interrupt_active(self) -> None:
        for active in list(self.active.values()):
            job = active.job
            if job.container_name:
                docker_stop(job.container_name)
            if active.process is not None and active.process.poll() is None:
                active.process.terminate()
        deadline = time.monotonic() + 10
        while self.active and time.monotonic() < deadline:
            self._reap_finished()
            time.sleep(0.2)
        for slot, active in list(self.active.items()):
            if active.process is not None and active.process.poll() is None:
                active.process.kill()
            if active.log_file:
                active.log_file.close()
            job = active.job
            job.state = "interrupted"
            job.finished_at = now_iso()
            job.exit_status = active.process.poll() if active.process is not None else self._poll_tmux_job(job)
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
        if force or final or now - self.last_plain_log >= self.args.status_interval:
            self.last_plain_log = now
            counts = state_counts(self.jobs)
            line = (
                f"[{now_iso()}] elapsed={format_duration(int(now - self.start_monotonic))} "
                f"planned={counts['planned']} running={counts['running']} done={counts['done']} "
                f"timed_out={counts['timed_out']} failed={counts['failed']} interrupted={counts['interrupted']}"
            )
            print(line, flush=True)
            if self.args.verbose:
                active_jobs = ", ".join(
                    f"slot={slot}:job={active.job.job_id}:cpu={active.job.cpu}:crashes={get_crash_stats(active.job)['crash_count']}"
                    for slot, active in sorted(self.active.items())
                )
                print(f"[{now_iso()}] active: {active_jobs or '<none>'}", flush=True)

    def _verbose(self, message: str) -> None:
        if self.args.verbose:
            print(f"[{now_iso()}] {message}", flush=True)


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


def redact_value(key: str, value: str) -> str:
    if key in SECRET_ENV_KEYS or "TOKEN" in key or "SECRET" in key or "PASSWORD" in key:
        return "<set>" if value else ""
    return value


def redact_cmd(cmd: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next_env = False
    for part in cmd:
        if redact_next_env:
            key, sep, value = part.partition("=")
            redacted.append(f"{key}{sep}{redact_value(key, value)}" if sep else part)
            redact_next_env = False
            continue
        redacted.append(part)
        if part in {"-e", "--env"}:
            redact_next_env = True
    return redacted


def quote_redacted_cmd(cmd: list[str]) -> str:
    return quote_cmd(redact_cmd(cmd))


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
        return sorted(path.resolve() for path in root.iterdir() if path.is_dir() and not has_ignore_file(path))

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


def has_ignore_file(path: Path) -> bool:
    return any(child.is_file() and child.name.startswith("IGNORE") for child in path.iterdir())


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
    for repeat_index in range(1, repeat + 1):
        for harness in harnesses:
            base = safe_name(harness.name)
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
        "run_dir": str(run_dir),
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
        "tmux_session": args.tmux_session,
        "verbose": args.verbose,
        "status_interval": args.status_interval,
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
            out[key] = redact_value(key, value)
    return out


def append_scheduler_log(run_dir: Path, message: str) -> None:
    with (run_dir / "scheduler.log").open("a") as fh:
        fh.write(f"[{now_iso()}] {message}\n")


def append_event(run_dir: Path, event: str, **fields: Any) -> None:
    payload = {"ts": now_iso(), "event": event, **fields}
    with (run_dir / "events.jsonl").open("a") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")


def job_to_state(job: Job) -> dict[str, Any]:
    crash_stats = get_crash_stats(job)
    afl_stats = read_afl_stats(job.out_dir)
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
        "afl_stats": afl_stats,
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
    try:
        candidates.extend(sorted(crash_root.glob("crashes.*")))
    except OSError as exc:
        return {"crash_count": 0, "latest_crash": None, "error": str(exc)}
    crashes: list[Path] = []
    for crash_dir in candidates:
        try:
            if not crash_dir.is_dir():
                continue
            children = list(crash_dir.iterdir())
        except OSError:
            continue
        for item in children:
            try:
                is_file = item.is_file()
            except OSError:
                is_file = False
            if is_file and item.name != "README.txt":
                crashes.append(item)
    try:
        latest = max(crashes, key=lambda path: path.stat().st_mtime, default=None)
    except OSError:
        latest = None
    return {"crash_count": len(crashes), "latest_crash": str(latest) if latest else None}


def update_crash_stats(_job: Job) -> None:
    # Crash stats are computed from disk when state is written.
    return


def read_afl_stats(out_dir: Path) -> dict[str, Any] | None:
    stats_path = out_dir / "default" / "fuzzer_stats"
    try:
        if not stats_path.is_file():
            return None
    except OSError as exc:
        return {"error": str(exc), "path": str(stats_path)}
    try:
        raw: dict[str, str] = {}
        for line in stats_path.read_text(errors="replace").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            raw[key.strip()] = value.strip()
    except OSError as exc:
        return {"error": str(exc), "path": str(stats_path)}
    if not raw:
        return None

    stats: dict[str, Any] = {"path": str(stats_path), "raw": raw}
    int_keys = {
        "start_time",
        "last_update",
        "run_time",
        "fuzzer_pid",
        "cycles_done",
        "cycles_wo_finds",
        "time_wo_finds",
        "fuzz_time",
        "calibration_time",
        "sync_time",
        "trim_time",
        "execs_done",
        "corpus_count",
        "corpus_favored",
        "corpus_found",
        "corpus_imported",
        "corpus_variable",
        "max_depth",
        "cur_item",
        "pending_favs",
        "pending_total",
        "saved_crashes",
        "saved_hangs",
        "total_tmout",
        "last_find",
        "last_crash",
        "last_hang",
        "execs_since_crash",
        "exec_timeout",
        "slowest_exec_ms",
        "peak_rss_mb",
        "edges_found",
        "total_edges",
    }
    float_keys = {"execs_per_sec", "execs_ps_last_min"}
    percent_keys = {"stability", "bitmap_cvg"}
    for key, value in raw.items():
        if key in int_keys:
            stats[key] = parse_int(value)
        elif key in float_keys:
            stats[key] = parse_float(value)
        elif key in percent_keys:
            stats[key] = parse_percent(value)
        elif key in {"afl_banner", "afl_version", "target_mode", "command_line"}:
            stats[key] = value
    now = int(time.time())
    if isinstance(stats.get("last_update"), int):
        stats["last_update_ago"] = max(0, now - stats["last_update"])
    if isinstance(stats.get("last_find"), int) and stats["last_find"] > 0:
        stats["last_find_ago"] = max(0, now - stats["last_find"])
    if isinstance(stats.get("last_crash"), int) and stats["last_crash"] > 0:
        stats["last_crash_ago"] = max(0, now - stats["last_crash"])
    return stats


def parse_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def parse_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def parse_percent(value: str) -> float | None:
    return parse_float(value.rstrip("%"))


def build_docker_command(args: argparse.Namespace, run_dir: Path, job: Job, cpu: str, interactive: bool = False) -> list[str]:
    container_harness = f"/srv/{job.harness.relpath.as_posix()}"
    container_job_dir = f"/campaign/jobs/{job.job_id}"
    fuzz_cmd = [
        "/srv/emulator/fuzz.sh",
        container_harness,
        "--in_dir",
        f"{container_job_dir}/in",
        "--out_dir",
        f"{container_job_dir}/out",
    ]
    if args.triage_hook:
        fuzz_cmd.extend(
            [
                "--triage_report_dir",
                f"{container_job_dir}/triage",
                "-I",
                args.triage_hook,
            ]
        )
    notify_cmd = [
        "/srv/medic/ntfy-hook.sh",
        "afl-stopped",
        container_harness,
        f"{container_job_dir}/out",
    ]
    shell = (
        "set -u; "
        "status=0; notified=0; "
        f"notify_stop() {{ if [ \"$notified\" -eq 0 ]; then notified=1; {quote_cmd(notify_cmd)} \"exit_status=$status\" || true; fi; }}; "
        "trap 'status=$?; notify_stop; exit $status' EXIT; "
        "trap 'status=130; notify_stop; exit $status' INT; "
        "trap 'status=143; notify_stop; exit $status' TERM; "
        f"{quote_cmd(fuzz_cmd)}; "
        "status=$?; "
        "exit $status"
    )

    cmd = [
        "docker",
        "run",
        "--rm",
    ]
    if interactive:
        cmd.append("-it")
    cmd.extend(
        [
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
    )

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


def rewrite_campaign_path(raw: str | None, run_dir: Path, original_run_dir: str | None) -> Path | None:
    if not raw:
        return None
    raw_path = Path(raw)
    if original_run_dir:
        original = Path(original_run_dir).as_posix().rstrip("/")
        raw_posix = raw_path.as_posix()
        if raw_posix == original:
            return run_dir
        if raw_posix.startswith(original + "/"):
            return run_dir / raw_posix[len(original) + 1 :]
    if raw_path.is_absolute():
        return raw_path
    return run_dir / raw_path


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def rewrite_job_path(raw: str | None, run_dir: Path, job_id: str | None) -> Path | None:
    if not raw:
        return None
    raw_posix = Path(raw).as_posix()
    if job_id:
        marker = f"/jobs/{job_id}/"
        if marker in raw_posix:
            return run_dir / "jobs" / job_id / raw_posix.split(marker, 1)[1]
        suffix = f"/jobs/{job_id}"
        if raw_posix.endswith(suffix):
            return run_dir / "jobs" / job_id
    raw_path = Path(raw)
    if raw_path.is_absolute():
        return raw_path
    return run_dir / raw_path


def campaign_container_path(local_path: Path, run_dir: Path) -> str:
    try:
        rel = local_path.resolve().relative_to(run_dir.resolve())
    except ValueError as exc:
        raise BatchError(f"path is not inside run-dir and cannot be mounted as /campaign: {local_path}") from exc
    return f"/campaign/{rel.as_posix()}"


def parse_artifact_kinds(raw: str) -> set[str]:
    aliases = {
        "crash": "crashes",
        "crashes": "crashes",
        "hang": "hangs",
        "hangs": "hangs",
    }
    kinds: set[str] = set()
    for part in raw.split(","):
        value = part.strip().lower()
        if not value:
            continue
        kind = aliases.get(value)
        if kind is None:
            raise BatchError(f"invalid --artifacts value: {part}; expected crashes, hangs, or both")
        kinds.add(kind)
    if not kinds:
        raise BatchError("--artifacts must select crashes, hangs, or both")
    return kinds


def parse_csv_filter(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def matches_any_pattern(values: list[str], patterns: list[str]) -> bool:
    if not patterns:
        return True
    for pattern in patterns:
        for value in values:
            if value == pattern or fnmatch.fnmatch(value, pattern):
                return True
    return False


def discover_triage_artifacts(out_dir: Path, artifact_kinds: set[str]) -> list[dict[str, Any]]:
    default_dir = out_dir / "default"
    if not default_dir.is_dir():
        return []
    artifacts: list[dict[str, Any]] = []
    for pattern, kind in (("crashes*", "crashes"), ("hangs*", "hangs")):
        if kind not in artifact_kinds:
            continue
        for artifact_dir in sorted(default_dir.glob(pattern)):
            if not artifact_dir.is_dir():
                continue
            for artifact in sorted(artifact_dir.iterdir()):
                if not artifact.is_file() or artifact.name == "README.txt":
                    continue
                stat = artifact.stat()
                artifacts.append(
                    {
                        "kind": kind,
                        "path": artifact,
                        "source_dir": artifact_dir,
                        "mtime": int(stat.st_mtime),
                        "size": stat.st_size,
                    }
                )
    artifacts.sort(key=lambda item: (item["mtime"], str(item["path"])))
    return artifacts


def triage_artifact_path_key(path: Path) -> str:
    parts = path.parts
    if "default" in parts:
        index = len(parts) - 1 - list(reversed(parts)).index("default")
        if index + 1 < len(parts):
            return Path(*parts[index + 1 :]).as_posix()
    return safe_artifact_name(path)


def triage_artifact_key(job_id: str, kind: str, path: Path, mtime: Any, size: Any) -> tuple[str, str, str, str, str]:
    return (str(job_id), str(kind), triage_artifact_path_key(path), str(mtime), str(size))


def processed_triage_artifact_keys(run_dir: Path) -> set[tuple[str, str, str, str, str]]:
    keys: set[tuple[str, str, str, str, str]] = set()
    backfill_root = run_dir / "backfill-triage"
    if not backfill_root.is_dir():
        return keys
    for manifest_path in sorted(backfill_root.glob("*/manifest.tsv")):
        try:
            with manifest_path.open(newline="") as manifest_fh:
                for row in csv.DictReader(manifest_fh, delimiter="\t"):
                    job_id = row.get("job_id")
                    kind = row.get("kind")
                    source_path = row.get("source_path")
                    mtime = row.get("mtime")
                    size = row.get("size")
                    if not job_id or not kind or not source_path or mtime is None or size is None:
                        continue
                    keys.add(triage_artifact_key(job_id, kind, Path(source_path), mtime, size))
        except (OSError, csv.Error):
            continue
    return keys


def safe_artifact_name(path: Path) -> str:
    parent = safe_name(path.parent.name)
    name = re.sub(r"[^A-Za-z0-9_.:+=,@%-]+", "_", path.name)
    return f"{parent}__{name}"


def parse_triage_output(output: str) -> tuple[str, str]:
    for line in reversed(output.splitlines()):
        if "\t" not in line:
            continue
        result_type, detail = line.split("\t", 1)
        if result_type in TRIAGE_RESULT_TYPES:
            return result_type, detail
    stripped = output.strip().replace("\n", " | ")
    return "triage-failed", f"reason=unparseable-output output={stripped[:500]}"


def build_replay_docker_command(
    args: argparse.Namespace,
    run_dir: Path,
    harness_relpath: str,
    fuzz_out: Path,
    report_dir: Path,
    artifact: Path,
) -> list[str]:
    cmd = [
        "docker",
        "run",
        "--rm",
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
        "-e",
        "AFL_NO_AFFINITY=1",
        "-e",
        "TAEMU_CRASH_NOTIMPL=1",
        "-e",
        f"REPLAY_FUZZ_TIMEOUT={args.replay_timeout}",
    ]
    for key in ("NTFY_TOKEN", "NTFY_TOPIC", "NTFY_URL"):
        if os.environ.get(key):
            cmd.extend(["-e", f"{key}={os.environ[key]}"])
    cmd.extend(
        [
            args.image,
            "/srv/medic/replay-fuzz.sh",
            f"/srv/{harness_relpath}",
            campaign_container_path(fuzz_out, run_dir),
            campaign_container_path(report_dir, run_dir),
            campaign_container_path(artifact, run_dir),
        ]
    )
    return cmd


def build_coverage_docker_command(
    args: argparse.Namespace,
    run_dir: Path,
    job_id: str,
    harness_relpath: str,
    out_dir: Path,
) -> list[str]:
    container_harness = f"/srv/{harness_relpath}"
    container_out = campaign_container_path(out_dir, run_dir)
    cov_dir = f"{container_out}/cov"
    merged = f"{container_out}/drcov.log"
    manifest = f"{container_out}/seed-coverage.tsv"
    summary = f"{container_out}/coverage-summary.tsv"
    log_dir = f"{container_out}/coverage-logs"
    replay_timeout = str(args.replay_timeout)
    shell = (
        "set -uo pipefail; "
        "shopt -s nullglob; "
        f"mkdir -p {shlex.quote(cov_dir)} {shlex.quote(log_dir)}; "
        f"tmp_root={shlex.quote(container_out)}/.coverage-replay-tmp/replay-$$; "
        "rm -rf \"$tmp_root\"; "
        "mkdir -p \"$tmp_root\"; "
        "cleanup() { rm -rf \"$tmp_root\"; }; "
        "trap cleanup EXIT; "
        "tmp_manifest=\"$tmp_root/seed-coverage.tsv\"; "
        "tmp_summary=\"$tmp_root/coverage-summary.tsv\"; "
        "printf 'seed\\tcov\\texit_status\\tstatus\\tlog\\n' > \"$tmp_manifest\"; "
        "status=0; count=0; skipped=0; replayed=0; failed=0; "
        f"for file in {shlex.quote(container_out)}/*/queue/*; do "
        "[[ -e \"$file\" ]] || continue; "
        "count=$((count + 1)); "
        "base=$(basename \"$file\"); "
        "safe=${base//[^A-Za-z0-9_.:+=,@%-]/_}; "
        f"cov={shlex.quote(cov_dir)}/\"$base\".cov; "
        f"log={shlex.quote(log_dir)}/\"$safe\".log; "
        "if [[ -s \"$cov\" && -s \"$log\" ]]; then "
        "skipped=$((skipped + 1)); "
        "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$file\" \"$cov\" 0 skipped \"$log\" >> \"$tmp_manifest\"; "
        "continue; "
        "fi; "
        "seed_tmp=\"$tmp_root/$safe\"; "
        "tmp_out=\"$seed_tmp/out\"; "
        "tmp_log=\"$seed_tmp/replay.log\"; "
        "mkdir -p \"$tmp_out\"; "
        "set +e; "
        f"TAEMU_COV_OUT_DIR=\"$tmp_out\" timeout -k 5 {shlex.quote(replay_timeout)} "
        f"/srv/emulator/fuzz.sh {shlex.quote(container_harness)} \"$file\" >\"$tmp_log\" 2>&1; "
        "rc=$?; "
        "set -e; "
        "tmp_cov=\"$tmp_out/cov/$base.cov\"; "
        "if [[ -s \"$tmp_cov\" ]]; then "
        "mv -f \"$tmp_log\" \"$log\"; "
        "mv -f \"$tmp_cov\" \"$cov\"; "
        "replayed=$((replayed + 1)); "
        "seed_status=replayed; "
        "if [[ \"$rc\" -ne 0 ]]; then seed_status=replayed-nonzero; fi; "
        "else "
        "failed=$((failed + 1)); "
        "status=1; "
        "seed_status=failed-no-cov; "
        "fi; "
        "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$file\" \"$cov\" \"$rc\" \"$seed_status\" \"$log\" >> \"$tmp_manifest\"; "
        "done; "
        f"cov_files=( {shlex.quote(cov_dir)}/*.cov ); "
        "if [ ${#cov_files[@]} -gt 0 ]; then "
        "tmp_merged=\"$tmp_root/drcov.log\"; "
        f"if /opt/afl/drcov-merge -u \"$tmp_merged\" \"${{cov_files[@]}}\"; then "
        f"mv -f \"$tmp_merged\" {shlex.quote(merged)}; "
        "else "
        "status=1; "
        "fi; "
        "else "
        "status=1; "
        "fi; "
        f"printf 'job_id\\tseeds\\tskipped\\treplayed\\tfailed\\tstatus\\tmerged\\n%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' {shlex.quote(job_id)} \"$count\" \"$skipped\" \"$replayed\" \"$failed\" \"$status\" {shlex.quote(merged)} > \"$tmp_summary\"; "
        f"mv -f \"$tmp_manifest\" {shlex.quote(manifest)}; "
        f"mv -f \"$tmp_summary\" {shlex.quote(summary)}; "
        "exit $status"
    )

    cmd = [
        "docker",
        "run",
        "--rm",
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
        "-e",
        "AFL_NO_AFFINITY=1",
        "-e",
        "TAEMU_CRASH_NOTIMPL=1",
        "-e",
        f"REPLAY_TIMEOUT={args.replay_timeout}",
        args.image,
        "bash",
        "-lc",
        shell,
    ]
    return cmd


def notify_backfill_real_crash(harness_path: str, fuzz_out: Path, detail: str) -> None:
    subprocess.run(
        [str(REPO_ROOT / "medic" / "ntfy-hook.sh"), "real-crash", harness_path, str(fuzz_out), detail],
        cwd=REPO_ROOT,
        check=False,
    )


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


def enrich_state(run_dir: Path, state: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(state)
    job_id = str(enriched.get("job_id") or "")
    for key in ("job_dir", "in_dir", "out_dir", "triage_dir", "log_path"):
        rewritten = rewrite_job_path(enriched.get(key), run_dir, job_id)
        if rewritten:
            enriched[key] = str(rewritten)
    out_dir = rewrite_job_path(enriched.get("out_dir"), run_dir, job_id)
    if out_dir:
        afl_stats = read_afl_stats(out_dir)
        if afl_stats is not None:
            enriched["afl_stats"] = afl_stats
            if afl_stats.get("saved_crashes") is not None:
                enriched["crash_count"] = afl_stats["saved_crashes"]
    return enriched


def enrich_states(run_dir: Path, states: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [enrich_state(run_dir, state) for state in states]


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


def aggregate_afl(states: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        "execs_done": 0,
        "execs_per_sec": 0.0,
        "saved_crashes": 0,
        "saved_hangs": 0,
        "total_tmout": 0,
    }
    seen = 0
    stale: list[dict[str, Any]] = []
    for state in states:
        stats = state.get("afl_stats") or {}
        if not stats or stats.get("error"):
            continue
        seen += 1
        for key in ("execs_done", "saved_crashes", "saved_hangs", "total_tmout"):
            if isinstance(stats.get(key), int):
                totals[key] += stats[key]
        if isinstance(stats.get("execs_per_sec"), float):
            totals["execs_per_sec"] += stats["execs_per_sec"]
        if state.get("state") == "running" and isinstance(stats.get("last_update_ago"), int) and stats["last_update_ago"] > 120:
            stale.append(state)
    totals["jobs_with_afl_stats"] = seen
    totals["stale_running_jobs"] = stale
    return totals


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


def format_stat_duration(value: Any) -> str:
    if isinstance(value, int):
        return format_duration(value)
    return "-"


def format_int(value: Any) -> str:
    if isinstance(value, int):
        return str(value)
    return "-"


def format_float(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    if isinstance(value, int):
        return str(value)
    return "-"


def format_percent(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}%"
    if isinstance(value, int):
        return f"{value}%"
    return "-"


def format_ago(value: Any) -> str:
    if isinstance(value, int):
        return f"{format_duration(value)} ago"
    return "-"


def cmd_start(args: argparse.Namespace) -> int:
    cpus, harnesses = validate_preflight(args)
    run_dir = Path(args.run_dir).resolve()
    jobs = generate_jobs(run_dir, harnesses, args.repeat)

    if args.dry_run:
        tmux = f", tmux_session={args.tmux_session}" if args.tmux_session else ""
        print(f"dry-run ok: {len(harnesses)} harnesses, {len(jobs)} jobs, slots={args.slots}, cpus={','.join(cpus)}{tmux}")
        for job in jobs:
            print(f"{job.job_id}\t{job.harness.relpath}\trepeat={job.repeat_index}")
        return 0

    create_run_layout(run_dir)
    materialize_jobs(jobs)
    write_campaign_files(args, cpus, harnesses, jobs)
    append_scheduler_log(run_dir, f"created campaign jobs={len(jobs)} slots={args.slots} cpus={','.join(cpus)}")
    if args.verbose:
        print(f"campaign: {run_dir}")
        print(f"scheduler log: {run_dir / 'scheduler.log'}")
        print(f"events: {run_dir / 'events.jsonl'}")
        print(f"status dir: {run_dir / 'status'}")
        print(f"jobs dir: {run_dir / 'jobs'}")
        print(f"jobs={len(jobs)} harnesses={len(harnesses)} slots={args.slots} cpus={','.join(cpus)}")
    if args.tmux_session:
        append_scheduler_log(run_dir, f"tmux session requested: {args.tmux_session}")
        print(f"AFL screens will be in tmux session: {args.tmux_session}")
        print(f"Attach with: tmux attach -t {args.tmux_session}")
    scheduler = Scheduler(args=args, cpus=cpus, run_dir=run_dir, status_dir=run_dir / "status", jobs=jobs)
    return scheduler.run()


def resolved_run_dir(args: argparse.Namespace) -> Path:
    raw = getattr(args, "run_dir", None) or getattr(args, "run_dir_pos", None)
    if not raw:
        raise BatchError("run-dir is required")
    return Path(raw).resolve()


def cmd_status(args: argparse.Namespace) -> int:
    run_dir = resolved_run_dir(args)
    states = enrich_states(run_dir, read_states(run_dir))
    counts = state_counts_from_states(states)
    afl = aggregate_afl(states)
    active = [state for state in states if state.get("state") == "running"]
    failures = [state for state in states if state.get("state") in {"failed", "interrupted"}]

    summary = {
        "run_dir": str(run_dir),
        "totals": counts,
        "afl": afl,
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
    print(
        f"afl: stats_jobs={afl['jobs_with_afl_stats']} execs={afl['execs_done']} "
        f"execs/sec={afl['execs_per_sec']:.2f} crashes={afl['saved_crashes']} "
        f"hangs={afl['saved_hangs']} timeouts={afl['total_tmout']}"
    )
    if active:
        print("active:")
        for state in active:
            stats = state.get("afl_stats") or {}
            print(
                f"  slot={state.get('slot')} cpu={state.get('cpu')} job={state.get('job_id')} "
                f"harness={state.get('harness')} runtime={format_stat_duration(stats.get('run_time'))} "
                f"eps={format_float(stats.get('execs_per_sec'))} execs={format_int(stats.get('execs_done'))} "
                f"corpus={format_int(stats.get('corpus_count'))} crashes={format_int(stats.get('saved_crashes'))} "
                f"hangs={format_int(stats.get('saved_hangs'))} bitmap={format_percent(stats.get('bitmap_cvg'))} "
                f"stability={format_percent(stats.get('stability'))} updated={format_ago(stats.get('last_update_ago'))}"
            )
    stale_jobs = afl["stale_running_jobs"]
    if stale_jobs:
        print("stale running jobs:")
        for state in stale_jobs[:10]:
            stats = state.get("afl_stats") or {}
            print(f"  job={state.get('job_id')} last_update={format_ago(stats.get('last_update_ago'))} stats={stats.get('path')}")
    if failures:
        print("recent failures:")
        for state in failures[-10:]:
            print(f"  {state.get('state')} exit={state.get('exit_status')} job={state.get('job_id')} log={state.get('log_path')}")
    completed = [state for state in states if state.get("state") in {"done", "timed_out"}]
    if completed:
        print("recent completed:")
        for state in completed[-10:]:
            stats = state.get("afl_stats") or {}
            print(
                f"  {state.get('state')} job={state.get('job_id')} "
                f"execs={format_int(stats.get('execs_done'))} crashes={format_int(stats.get('saved_crashes'))} "
                f"hangs={format_int(stats.get('saved_hangs'))} log={state.get('log_path')}"
            )
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    run_dir = resolved_run_dir(args)
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


def cmd_watch(args: argparse.Namespace) -> int:
    args.run_dir = str(resolved_run_dir(args))
    args.json = False
    try:
        while True:
            sys.stdout.write("\x1b[2J\x1b[H")
            cmd_status(args)
            sys.stdout.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130


def cmd_doctor(args: argparse.Namespace) -> int:
    run_dir = resolved_run_dir(args)
    issues: list[str] = []
    warnings: list[str] = []
    if not run_dir.is_dir():
        raise BatchError(f"run-dir not found: {run_dir}")
    if not (run_dir / "status").is_dir():
        issues.append(f"missing status directory: {run_dir / 'status'}")
    if not (run_dir / "jobs").is_dir():
        issues.append(f"missing jobs directory: {run_dir / 'jobs'}")

    states = read_states(run_dir) if (run_dir / "status").is_dir() else []
    enriched = enrich_states(run_dir, states)
    for state in enriched:
        job_id = state.get("job_id", "<unknown>")
        job_state = state.get("state")
        for key in ("out_dir", "log_path"):
            raw = state.get(key)
            if not raw:
                if not (key == "log_path" and job_state == "planned"):
                    warnings.append(f"{job_id}: missing {key}")
                continue
            path = Path(raw)
            if key == "out_dir" and not path.is_dir():
                warnings.append(f"{job_id}: output directory not found: {path}")
            if key == "log_path" and not path.exists():
                warnings.append(f"{job_id}: log file not found: {path}")
        stats = state.get("afl_stats")
        if isinstance(stats, dict) and stats.get("error"):
            warnings.append(f"{job_id}: cannot read AFL stats: {stats['error']}")

    for log_name in ("scheduler.log", "events.jsonl"):
        log_path = run_dir / log_name
        if not log_path.is_file():
            continue
        try:
            text = log_path.read_text(errors="replace")
        except OSError as exc:
            warnings.append(f"cannot read {log_path}: {exc}")
            continue
        if re.search(r"NTFY_TOKEN=(?!<set>)[^\s]+", text):
            issues.append(f"{log_path} appears to contain an unredacted NTFY_TOKEN")

    print(f"run_dir: {run_dir}")
    print(f"jobs: {len(states)}")
    if issues:
        print("issues:")
        for issue in issues:
            print(f"  {issue}")
    if warnings:
        print("warnings:")
        for warning in warnings[:50]:
            print(f"  {warning}")
        if len(warnings) > 50:
            print(f"  ... {len(warnings) - 50} more")
    if not issues and not warnings:
        print("doctor: ok")
    return 1 if issues else 0


def cmd_triage_missed(args: argparse.Namespace) -> int:
    run_dir = resolved_run_dir(args)
    if not run_dir.is_dir():
        raise BatchError(f"run-dir not found: {run_dir}")
    if not args.dry_run and shutil.which("docker") is None:
        raise BatchError("docker is not available on PATH")

    states = read_states(run_dir)
    allowed_states = {state.strip() for state in args.jobs.split(",") if state.strip()}
    if not allowed_states:
        raise BatchError("--jobs must contain at least one state")
    artifact_kinds = parse_artifact_kinds(args.artifacts)
    harness_patterns = parse_csv_filter(args.harnesses)
    processed_keys = set() if args.force else processed_triage_artifact_keys(run_dir)

    selected: list[dict[str, Any]] = []
    skipped_existing = 0
    for state in states:
        if state.get("state") not in allowed_states:
            continue
        job_id = state.get("job_id")
        harness_relpath = state.get("harness_relpath")
        if not job_id or not harness_relpath:
            continue
        harness_name = str(state.get("harness") or Path(harness_relpath).name)
        if not matches_any_pattern([str(job_id), harness_name, str(harness_relpath)], harness_patterns):
            continue
        out_dir = rewrite_campaign_path(state.get("out_dir"), run_dir, args.original_run_dir)
        if out_dir and not out_dir.exists():
            out_dir = rewrite_job_path(state.get("out_dir"), run_dir, job_id)
        if out_dir is None:
            out_dir = run_dir / "jobs" / job_id / "out"
        artifacts = discover_triage_artifacts(out_dir, artifact_kinds)
        for artifact in artifacts:
            artifact_key = triage_artifact_key(job_id, artifact["kind"], artifact["path"], artifact["mtime"], artifact["size"])
            if artifact_key in processed_keys:
                skipped_existing += 1
                continue
            selected.append(
                {
                    "state": state,
                    "job_id": job_id,
                    "harness_relpath": harness_relpath,
                    "out_dir": out_dir,
                    "artifact": artifact,
                    "artifact_key": artifact_key,
                }
            )

    if args.dry_run:
        force_note = " force=true" if args.force else ""
        print(
            f"dry-run: jobs={len({item['job_id'] for item in selected})} "
            f"artifacts={len(selected)} skipped_existing={skipped_existing}{force_note}"
        )
        for item in selected[: args.limit or len(selected)]:
            artifact = item["artifact"]
            print(f"{item['job_id']}\t{artifact['kind']}\t{artifact['path']}")
        if args.limit and len(selected) > args.limit:
            print(f"... {len(selected) - args.limit} more artifacts omitted by --limit")
        return 0

    if not selected:
        force_note = " with --force" if not args.force else ""
        print(f"triage-missed: no new artifacts to process; skipped_existing={skipped_existing}{force_note}")
        return 0

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backfill_dir = run_dir / "backfill-triage" / timestamp
    artifacts_root = backfill_dir / "artifacts"
    reports_root = backfill_dir / "reports"
    backfill_dir.mkdir(parents=True)
    artifacts_root.mkdir()
    reports_root.mkdir()

    manifest_path = backfill_dir / "manifest.tsv"
    results_jsonl = backfill_dir / "results.jsonl"
    summary_tsv = backfill_dir / "summary.tsv"
    text_outputs = {
        "real-crash": backfill_dir / "real-crashes.txt",
        "function-missing": backfill_dir / "function-missing.txt",
        "hang": backfill_dir / "hangs.txt",
        "triage-failed": backfill_dir / "triage-failed.txt",
    }
    counts = {result_type: 0 for result_type in TRIAGE_RESULT_TYPES}

    with manifest_path.open("w", newline="") as manifest_fh, summary_tsv.open("w", newline="") as summary_fh:
        manifest = csv.writer(manifest_fh, delimiter="\t")
        summary = csv.writer(summary_fh, delimiter="\t")
        manifest.writerow(["job_id", "kind", "source_path", "local_copy", "mtime", "size"])
        summary.writerow(["job_id", "kind", "result", "replay_status", "source_path", "local_copy", "report_dir", "detail"])

        for index, item in enumerate(selected, start=1):
            if args.limit and index > args.limit:
                break
            artifact = item["artifact"]
            job_id = item["job_id"]
            kind = artifact["kind"]
            source_path = artifact["path"]
            local_artifact_dir = artifacts_root / job_id / kind
            local_artifact_dir.mkdir(parents=True, exist_ok=True)
            local_copy = local_artifact_dir / safe_artifact_name(source_path)
            report_dir = reports_root / job_id / f"{index:06d}-{safe_name(kind)}"
            report_dir.mkdir(parents=True, exist_ok=True)

            try:
                shutil.copy2(source_path, local_copy)
                manifest.writerow([job_id, kind, source_path, local_copy, artifact["mtime"], artifact["size"]])
                cmd = build_replay_docker_command(
                    args,
                    run_dir,
                    item["harness_relpath"],
                    item["out_dir"],
                    report_dir,
                    local_copy,
                )
                completed = subprocess.run(
                    cmd,
                    cwd=REPO_ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=args.replay_timeout + 30,
                    check=False,
                )
                result_type, detail = parse_triage_output(completed.stdout)
                if completed.returncode != 0 and result_type != "triage-failed":
                    detail = f"{detail} docker_status={completed.returncode}"
            except Exception as exc:
                result_type = "triage-failed"
                detail = f"reason=exception error={exc}"

            counts[result_type] = counts.get(result_type, 0) + 1
            replay_status = "-"
            match = re.search(r"(?:^| )replay_status=([^ ]+)", detail)
            if match:
                replay_status = match.group(1)
            summary.writerow([job_id, kind, result_type, replay_status, source_path, local_copy, report_dir, detail])
            with results_jsonl.open("a") as results_fh:
                results_fh.write(
                    json.dumps(
                        {
                            "job_id": job_id,
                            "harness_relpath": item["harness_relpath"],
                            "kind": kind,
                            "result": result_type,
                            "replay_status": replay_status,
                            "source_path": str(source_path),
                            "local_copy": str(local_copy),
                            "report_dir": str(report_dir),
                            "detail": detail,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            with text_outputs.get(result_type, text_outputs["triage-failed"]).open("a") as out_fh:
                out_fh.write(f"{job_id}\t{kind}\t{source_path}\t{detail}\n")
            print(f"[{index}/{len(selected)}] {result_type} {job_id} {kind} {source_path}", flush=True)

            if result_type == "real-crash" and not args.no_notify:
                notify_backfill_real_crash(f"/srv/{item['harness_relpath']}", item["out_dir"], detail)

    print(
        "backfill complete: "
        + " ".join(f"{result_type}={counts.get(result_type, 0)}" for result_type in sorted(counts))
        + f" skipped_existing={skipped_existing} dir={backfill_dir}"
    )
    return 0


def select_campaign_jobs(args: argparse.Namespace) -> list[dict[str, Any]]:
    run_dir = resolved_run_dir(args)
    states = read_states(run_dir)
    original_run_dir = getattr(args, "original_run_dir", None)
    campaign_path = run_dir / "campaign.json"
    if original_run_dir is None and campaign_path.is_file():
        try:
            original_run_dir = json.loads(campaign_path.read_text()).get("run_dir")
        except (OSError, json.JSONDecodeError):
            original_run_dir = None
    allowed_states = {state.strip() for state in args.jobs.split(",") if state.strip()}
    if not allowed_states:
        raise BatchError("--jobs must contain at least one state")
    harness_patterns = parse_csv_filter(args.harnesses)
    selected: list[dict[str, Any]] = []
    for state in states:
        if state.get("state") not in allowed_states:
            continue
        job_id = state.get("job_id")
        harness_relpath = state.get("harness_relpath")
        if not job_id or not harness_relpath:
            continue
        harness_name = str(state.get("harness") or Path(harness_relpath).name)
        if not matches_any_pattern([str(job_id), harness_name, str(harness_relpath)], harness_patterns):
            continue
        out_dir = rewrite_campaign_path(state.get("out_dir"), run_dir, original_run_dir)
        if out_dir and not path_exists(out_dir):
            out_dir = rewrite_job_path(state.get("out_dir"), run_dir, str(job_id))
        if out_dir is None:
            out_dir = run_dir / "jobs" / str(job_id) / "out"
        selected.append(
            {
                "state": state,
                "job_id": str(job_id),
                "harness_relpath": str(harness_relpath),
                "out_dir": out_dir,
            }
        )
    selected.sort(key=lambda item: item["job_id"])
    return selected


def cmd_replay_coverage(args: argparse.Namespace) -> int:
    run_dir = resolved_run_dir(args)
    if not run_dir.is_dir():
        raise BatchError(f"run-dir not found: {run_dir}")
    if not args.dry_run and shutil.which("docker") is None:
        raise BatchError("docker is not available on PATH")

    selected = select_campaign_jobs(args)
    if args.limit:
        selected = selected[: args.limit]

    if args.dry_run:
        print(f"dry-run: jobs={len(selected)}")
        for item in selected:
            queue_count = sum(
                1
                for queue_dir in item["out_dir"].glob("*/queue")
                if queue_dir.is_dir()
                for seed in queue_dir.iterdir()
                if seed.is_file()
            )
            print(f"{item['job_id']}\t{item['harness_relpath']}\tseeds={queue_count}\tout={item['out_dir']}")
        return 0

    if not selected:
        print("replay-coverage: no jobs selected")
        return 0

    summary_path = run_dir / "coverage-replay.tsv"
    failures = 0

    with summary_path.open("w", newline="") as summary_fh:
        summary = csv.writer(summary_fh, delimiter="\t")
        summary.writerow(["job_id", "harness_relpath", "out_dir", "exit_status", "merged_drcov", "manifest", "docker_log"])
        for index, item in enumerate(selected, start=1):
            cmd = build_coverage_docker_command(
                args,
                run_dir,
                item["job_id"],
                item["harness_relpath"],
                item["out_dir"],
            )
            completed = subprocess.run(
                cmd,
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=None,
                check=False,
            )
            docker_log = item["out_dir"] / "coverage-replay-docker.log"
            docker_log.write_text(completed.stdout)
            merged = item["out_dir"] / "drcov.log"
            manifest = item["out_dir"] / "seed-coverage.tsv"
            if completed.returncode != 0:
                failures += 1
            summary.writerow([item["job_id"], item["harness_relpath"], item["out_dir"], completed.returncode, merged, manifest, docker_log])
            print(f"[{index}/{len(selected)}] coverage {item['job_id']} exit={completed.returncode} merged={merged}", flush=True)

    print(f"coverage replay complete: jobs={len(selected)} failures={failures} summary={summary_path}")
    return 1 if failures else 0


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
    start.add_argument(
        "--triage-hook",
        default=DEFAULT_TRIAGE_HOOK,
        help="new-crash hook to pass to fuzz.sh; disabled by default",
    )
    start.add_argument(
        "--tmux-session",
        help="run each active fuzz job in a tmux window with an interactive Docker TTY so the AFL screen is visible",
    )
    start.add_argument("--verbose", "-v", action="store_true", help="print detailed scheduler progress and paths")
    start.add_argument(
        "--status-interval",
        type=float,
        default=30.0,
        help="seconds between non-TTY status lines; default 30, useful with --verbose",
    )
    start.add_argument("--dry-run", action="store_true", help="run preflight and print planned jobs without starting")
    start.set_defaults(func=cmd_start)

    status = subparsers.add_parser("status", help="show campaign status")
    status.add_argument("run_dir_pos", nargs="?", help="campaign directory")
    status.add_argument("--run-dir", help="campaign directory")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    stop = subparsers.add_parser("stop", help="stop running containers recorded in a campaign")
    stop.add_argument("run_dir_pos", nargs="?", help="campaign directory")
    stop.add_argument("--run-dir", help="campaign directory")
    stop.set_defaults(func=cmd_stop)

    watch = subparsers.add_parser("watch", help="refresh campaign status until interrupted")
    watch.add_argument("run_dir_pos", nargs="?", help="campaign directory")
    watch.add_argument("--run-dir", help="campaign directory")
    watch.add_argument("--interval", type=float, default=5.0, help="refresh interval in seconds; default 5")
    watch.set_defaults(func=cmd_watch)

    doctor = subparsers.add_parser("doctor", help="check campaign layout, status readability, and log redaction")
    doctor.add_argument("run_dir_pos", nargs="?", help="campaign directory")
    doctor.add_argument("--run-dir", help="campaign directory")
    doctor.set_defaults(func=cmd_doctor)

    triage = subparsers.add_parser("triage-missed", help="replay and classify saved AFL crashes/hangs from a campaign")
    triage.add_argument("run_dir_pos", nargs="?", help="local campaign directory")
    triage.add_argument("--run-dir", help="local campaign directory")
    triage.add_argument(
        "--original-run-dir",
        help="original absolute campaign root embedded in status files; rewritten to --run-dir when reading artifacts",
    )
    triage.add_argument(
        "--jobs",
        default="running,done,timed_out,failed,interrupted",
        help="comma-separated job states to scan; default includes running/done/timed_out/failed/interrupted",
    )
    triage.add_argument(
        "--artifacts",
        default="crashes,hangs",
        help="artifact kinds to scan: crashes, hangs, or crashes,hangs; default crashes,hangs",
    )
    triage.add_argument(
        "--harnesses",
        help="comma-separated harness/job filters; matches harness name, harness relpath, or job id, with shell globs",
    )
    triage.add_argument("--replay-timeout", type=int, default=DEFAULT_REPLAY_TIMEOUT, help=f"default {DEFAULT_REPLAY_TIMEOUT}")
    triage.add_argument("--image", default=DEFAULT_IMAGE, help=f"Docker image; default {DEFAULT_IMAGE}")
    triage.add_argument("--limit", type=int, help="process at most this many artifacts")
    triage.add_argument("--no-notify", action="store_true", help="do not send ntfy notifications for real crashes")
    triage.add_argument("--force", action="store_true", help="replay artifacts even if prior triage-missed runs processed them")
    triage.add_argument("--dry-run", action="store_true", help="list selected artifacts without copying or replaying")
    triage.set_defaults(func=cmd_triage_missed)

    coverage = subparsers.add_parser(
        "replay-coverage",
        help="replay AFL queue seeds from a campaign and merge per-seed drcov basic-block coverage",
    )
    coverage.add_argument("run_dir_pos", nargs="?", help="local campaign directory")
    coverage.add_argument("--run-dir", help="local campaign directory")
    coverage.add_argument(
        "--original-run-dir",
        help="original absolute campaign root embedded in status files; rewritten to --run-dir when reading queues",
    )
    coverage.add_argument(
        "--jobs",
        default="done,timed_out,failed,interrupted",
        help="comma-separated job states to scan; default done,timed_out,failed,interrupted",
    )
    coverage.add_argument(
        "--harnesses",
        help="comma-separated harness/job filters; matches harness name, harness relpath, or job id, with shell globs",
    )
    coverage.add_argument("--replay-timeout", type=int, default=DEFAULT_REPLAY_TIMEOUT, help=f"per-seed timeout; default {DEFAULT_REPLAY_TIMEOUT}")
    coverage.add_argument("--image", default=DEFAULT_IMAGE, help=f"Docker image; default {DEFAULT_IMAGE}")
    coverage.add_argument("--limit", type=int, help="process at most this many jobs")
    coverage.add_argument("--dry-run", action="store_true", help="list selected jobs and queue seed counts without replaying")
    coverage.set_defaults(func=cmd_replay_coverage)

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
