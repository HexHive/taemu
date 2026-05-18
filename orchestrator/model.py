from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_TRIAGE_HOOK = "/srv/medic/auto-triage.sh"
DEFAULT_CONTAINER_PREFIX = "taemu-batch-fuzz-"
DEFAULT_IMAGE = "ta_emu"
DEFAULT_MEMORY = "8g"
DEFAULT_REPEAT = 5
DEFAULT_FUZZTIME = 86400
DEFAULT_FUZZTIME_GRACE = 60
DEFAULT_SHM_SIZE = "100g"
DEFAULT_REPLAY_TIMEOUT = 120
STOP_REQUEST_FILE = "STOP_REQUESTED"
STATE_ORDER = ("planned", "running", "done", "timed_out", "failed", "interrupted")
TRIAGE_RESULT_TYPES = {"real-crash", "function-missing", "hang", "triage-failed"}
SECRET_ENV_KEYS = {"NTFY_TOKEN"}


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
    process: subprocess.Popen[Any] | None
    log_file: Any
