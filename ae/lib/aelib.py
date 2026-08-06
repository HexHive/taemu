"""Shared helpers for the Oversharing artifact-evaluation experiments.

Everything in here is deliberately dependency-free (standard library only) so
that the driver scripts run on a bare Linux host; all heavy lifting happens
inside the emulator container.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

AE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# TAEMU_ROOT is the repository path *on the docker host*; inside the AE
# controller the repository is mounted at exactly that path, so both agree.
REPO_DIR = os.environ.get("TAEMU_ROOT") or os.path.dirname(AE_DIR)
RESULTS_DIR = os.path.join(AE_DIR, "results")

TEES = ["teegris", "qsee", "kinibi", "mitee", "beanpod"]

# ---------------------------------------------------------------- environment


def cfg(name, default):
    """Read an AE_* setting from the environment (see ae/config.env)."""
    return os.environ.get(name, default)


def image():
    return cfg("AE_IMAGE", "ta_emu_ae")


def jobs():
    """How many emulators to run in parallel.

    An emulator saturates one core and needs ~85 MB, so the machine is sized by
    both CPU and available memory (the smaller wins). ae/config.env computes the
    same value for the shell side; this is the fallback when an experiment is
    started directly.
    """
    n = cfg("AE_JOBS", None)
    if n:
        return max(1, int(n))
    by_cpu = max(1, (os.cpu_count() or 2) - 2)
    by_mem = by_cpu
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    avail_mb = int(line.split()[1]) // 1024
                    by_mem = (avail_mb - int(cfg("AE_RESERVE_MB", "2048"))) \
                        // int(cfg("AE_MEM_PER_JOB_MB", "512"))
                    break
    except OSError:
        pass
    return max(1, min(by_cpu, max(1, by_mem), int(cfg("AE_MAX_JOBS", "64"))))


# ------------------------------------------------------------------- printing

C = {
    "red": "\033[1;31m",
    "grn": "\033[1;32m",
    "yel": "\033[1;33m",
    "blu": "\033[1;34m",
    "rst": "\033[0m",
}


def log(msg):
    print(f"{C['blu']}[ae]{C['rst']} {msg}", flush=True)


def ok(msg):
    print(f"{C['grn']}[ok]{C['rst']} {msg}", flush=True)


# Advisory notes collected during a run. They are not printed: an experiment's
# output is its table and its checks. They end up in notes.log and in the
# "notes" field of result.json, next to the numbers they qualify.
NOTES = []


def warn(msg):
    NOTES.append(str(msg))


def fail(msg):
    print(f"{C['red']}[--]{C['rst']} {msg}", flush=True)


def banner(title):
    print()
    print(f"{C['blu']}{'=' * 64}{C['rst']}")
    print(f"{C['blu']} {title}{C['rst']}")
    print(f"{C['blu']}{'=' * 64}{C['rst']}", flush=True)


# --------------------------------------------------------------------- docker


def docker_run(command, timeout=None, env=None, capture=True):
    """Run `command` (a shell string) inside a throw-away emulator container.

    The repository is bind-mounted at /srv and the working directory is
    /srv/emulator, so paths handed to the emulator scripts look like
    "../mitee/harness/377e_fuzz".
    """
    argv = [
        "docker", "run", "--rm", "--network", "host",
        "-v", f"{REPO_DIR}:/srv", "-w", "/srv/emulator",
        "-v", "/dev/shm:/dev/shm", "--ipc=host",
        "-e", f"REDIS_HOST={cfg('AE_REDIS_HOST', 'localhost')}",
        "-e", f"REDIS_PORT={cfg('AE_REDIS_PORT', '6379')}",
    ]
    for k, v in (env or {}).items():
        argv += ["-e", f"{k}={v}"]
    argv += [image(), "bash", "-c", command]
    try:
        p = subprocess.run(
            argv,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            timeout=timeout,
        )
        out = (p.stdout or b"").decode("utf-8", "replace")
        return p.returncode, out
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if e.stdout else ""
        return 124, out + "\n[ae] TIMEOUT\n"


def parallel(fn, items, workers=None):
    """Map `fn` over `items` with a bounded thread pool (one container each)."""
    workers = workers or jobs()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


# ------------------------------------------------------------- crash analysis

# The emulator signals a memory-safety violation either through a Unicorn
# exception (invalid fetch/read/write, i.e. a corrupted pointer or return
# address) or through its binary-only ASAN, which redirects the PC to
# CRASH_PC (0xdeadbeef) and logs the offending access.
CRASH_PATTERNS = [
    (r"out-of-bound (read|write) on address", "asan-oob"),
    (r"uaf on address", "asan-uaf"),
    (r"UC_ERR_FETCH_UNMAPPED", "invalid-fetch"),
    (r"UC_ERR_READ_UNMAPPED", "invalid-read"),
    (r"UC_ERR_WRITE_UNMAPPED", "invalid-write"),
    (r"UC_ERR_EXCEPTION", "cpu-exception"),
    (r"Invalid memory (fetch|read|write)", "invalid-access"),
    (r"0xdeadbeef", "crash-pc"),
]


def classify_crash(output):
    """Return the list of crash indicators observed in an emulator log."""
    seen = []
    for pattern, name in CRASH_PATTERNS:
        if re.search(pattern, output, re.IGNORECASE):
            if name not in seen:
                seen.append(name)
    return seen


def df_not_reproduced(output):
    return "double fetch location not reproduced" in output


def df_validated(output):
    """True if Distillation confirmed the crash needs the shared-memory race."""
    return "df validated" in output


# ------------------------------------------------- snapshot (job) enumeration


def snapshots_from_meta(meta_path):
    """Enumerate the Fetch-Anchored-Fuzzing snapshots encoded in one .meta file.

    A snapshot is identified by (seed, reg_hash): the Exploration seed that
    reached the overlapped fetch, and the hash of the register state at the
    second fetch. Contiguous second fetches issued from the same instruction
    are merged into one snapshot, mirroring
    swarm::job_generation::get_context_via_meta.
    """
    try:
        data = json.load(open(meta_path))
    except Exception:
        return []
    seed = data.get("key")
    if not seed:
        return []
    ctx = []
    for rec in data.get("records", []):
        regs = rec.get("regs")
        if not regs:
            continue
        if not rec.get("is_second_fetch", False):
            continue
        if not regs.get("is_read", False):
            continue
        reg_hash = regs.get("reg_hash")
        if reg_hash is None:
            continue
        ctx.append({
            "seed": seed,
            "reg_hash": str(reg_hash),
            "addr": rec.get("addr", 0),
            "size": rec.get("size") or 0,
            "pc": regs.get("PC", 0),
            "ret": regs.get("ret_addr", 0),
        })
    ctx.sort(key=lambda c: c["addr"])
    merged = []
    for c in ctx:
        p = merged[-1] if merged else None
        if p and p["addr"] + p["size"] == c["addr"] and p["pc"] == c["pc"] and p["ret"] == c["ret"]:
            p["size"] += c["size"]
        else:
            merged.append(dict(c))
    return merged


def overlapped_fetches(meta_path):
    """Number of annotated second fetches (overlapped fetches) in a .meta."""
    try:
        data = json.load(open(meta_path))
    except Exception:
        return 0
    return sum(1 for r in data.get("records", [])
               if r.get("is_second_fetch") and r.get("regs", {}).get("is_read"))


def harness_snapshots(harness_dir, require_seed=True):
    """All snapshots of a harness, derived from its deduplicated seeds."""
    sus = os.path.join(harness_dir, "in", "suspicious_inputs_replay")
    out = []
    if not os.path.isdir(sus):
        return out
    for name in sorted(os.listdir(sus)):
        if not name.endswith(".meta"):
            continue
        seed_path = os.path.join(sus, name[: -len(".meta")])
        if require_seed and not os.path.exists(seed_path):
            continue
        for snap in snapshots_from_meta(os.path.join(sus, name)):
            snap["harness"] = harness_dir
            snap["seed_path"] = seed_path
            snap["name"] = f"{snap['seed']}_{snap['reg_hash']}"
            out.append(snap)
    return out


def harness_crashes(harness_dir):
    """Crashing inputs produced by Fetch-Anchored Fuzzing for a harness.

    Returns dicts with the snapshot the crash belongs to, the crashing input,
    and whether Distillation already marked it as shared-memory-only (.df).
    """
    df_dir = os.path.join(harness_dir, "df_fuzz")
    res = []
    if not os.path.isdir(df_dir):
        return res
    for snap in sorted(os.listdir(df_dir)):
        cdir = os.path.join(df_dir, snap, "out", "default", "crashes")
        if not os.path.isdir(cdir):
            continue
        seed = "_".join(snap.split("_")[:-1])
        reg_hash = snap.split("_")[-1]
        seed_path = os.path.join(harness_dir, "in", "suspicious_inputs_replay", seed)
        for f in sorted(os.listdir(cdir)):
            if not f.startswith("id:"):
                continue
            if f.endswith(".output") or f.endswith(".df"):
                continue
            res.append({
                "harness": harness_dir,
                "snapshot": snap,
                "seed": seed,
                "seed_path": seed_path,
                "reg_hash": reg_hash,
                "crash": os.path.join(cdir, f),
                "distilled": os.path.exists(os.path.join(cdir, f + ".df")),
                "replayable": os.path.exists(seed_path) and os.path.exists(seed_path + ".meta"),
            })
    return res


def all_harnesses(root=REPO_DIR):
    """Every fuzzing harness in the artifact (TEE/harness/<name>)."""
    out = []
    for tee in sorted(os.listdir(root)):
        hdir = os.path.join(root, tee, "harness")
        if not os.path.isdir(hdir):
            continue
        for name in sorted(os.listdir(hdir)):
            h = os.path.join(hdir, name)
            if not os.path.isdir(h):
                continue
            if not os.path.exists(os.path.join(h, "harness.py")):
                continue
            if not ta_of(h):
                continue
            out.append(h)
    return out


# The five TEEs of Table I. Kinibi TAs are emulated with the Beanpod runtime and
# their harnesses live under beanpod/harness, so they are covered by "beanpod".
# optee/ holds the Rust TAs of Table IV, which E7 runs separately.
CAMPAIGN_TEES = ["teegris", "qsee", "mitee", "beanpod"]


def campaign_harnesses(root=REPO_DIR):
    """One harness per TA of the paper's campaign - the 30 TAs that operate on
    shared memory (Table I, '# TAs w/o Local Copy').

    Several harnesses can target the same TA (mitee/harness/377e_fuzz and
    mitee/harness/377e_double_fetch_stackov); only one of them is returned, so
    a TA is not fuzzed twice. Harnesses that carry a double-fetch name are
    preferred, since those are the ones the paper's campaign used.
    """
    by_ta = {}
    for h in all_harnesses(root):
        rel = os.path.relpath(h, root)
        tee = rel.split(os.sep)[0]
        if tee not in CAMPAIGN_TEES or os.path.basename(h).startswith("ae_"):
            continue
        ta = os.path.basename(os.path.realpath(ta_of(h)))
        prev = by_ta.get((tee, ta))
        if prev is None or ("double_fetch" in h and "double_fetch" not in prev):
            by_ta[(tee, ta)] = h
    return sorted(by_ta.values())


def resolve_harnesses(selected=None):
    """Turn --harnesses / $AE_SUBSET into a list of harness directories.

    "all" selects every harnessed TA of the campaign (the paper's 30).
    """
    if not selected:
        selected = ae_subset()
    if len(selected) == 1 and selected[0] == "all":
        return campaign_harnesses()
    out = []
    for h in selected:
        p = h if os.path.isabs(h) else os.path.join(REPO_DIR, h)
        if os.path.exists(os.path.join(p, "harness.py")):
            out.append(p)
        else:
            warn(f"{h}: no harness.py, skipped")
    return out


def ae_subset():
    return [x for x in cfg("AE_SUBSET", "").split() if x.strip()]


def ta_of(harness_dir):
    for f in sorted(os.listdir(harness_dir)):
        if f.endswith(".ta") and os.path.exists(os.path.join(harness_dir, f)):
            return os.path.join(harness_dir, f)
    return None


# ------------------------------------------------------ scratch harness trees


def stage_harness(src_harness, dst, seeds=(), crashes=()):
    """Copy the *inputs* of a harness into a fresh working tree.

    Experiments never write into the shipped campaign directories: they stage a
    minimal harness (harness.py + TA + selected seeds/crashes) under
    ae/results/ and let the emulator produce its output there.
    """
    os.makedirs(dst, exist_ok=True)
    shutil.copy(os.path.join(src_harness, "harness.py"), dst)
    # The TA is linked, not copied: tools that look for data next to the binary
    # (e.g. the CFG in <tee>/tas/bbs/ used by eval/graphs) resolve the symlink
    # and would not find it inside a staged harness.
    ta = os.path.realpath(ta_of(src_harness))
    base = ta[: -len(".ta")]
    for f in (ta, base + ".json"):
        if os.path.exists(f):
            link = os.path.join(dst, os.path.basename(f))
            if not os.path.exists(link):
                os.symlink(os.path.relpath(f, dst), link)
    for extra in ("init_fuzz.py",):
        p = os.path.join(src_harness, extra)
        if os.path.exists(p):
            shutil.copy(p, dst)
    sus = os.path.join(dst, "in", "suspicious_inputs_replay")
    os.makedirs(sus, exist_ok=True)
    for seed in seeds:
        for suffix in ("", ".meta"):
            p = seed + suffix
            if os.path.exists(p):
                shutil.copy(p, os.path.join(sus, os.path.basename(p)))
    for c in crashes:
        cdir = os.path.join(dst, "df_fuzz", c["snapshot"], "out", "default", "crashes")
        os.makedirs(cdir, exist_ok=True)
        shutil.copy(c["crash"], os.path.join(cdir, os.path.basename(c["crash"])))
    return dst


def in_container(path):
    """Translate a host path inside the repo to its path in the container."""
    rel = os.path.relpath(os.path.abspath(path), REPO_DIR)
    return os.path.join("/srv", rel)


def rel_to_emulator(path):
    """Path as the emulator scripts expect it (relative to /srv/emulator)."""
    return os.path.relpath(in_container(path), "/srv/emulator")


# -------------------------------------------------------------------- reports


def write_report(name, payload):
    """Persist a machine-readable result next to the experiment's logs."""
    d = os.path.join(RESULTS_DIR, name)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "result.json")
    payload = dict(payload)
    payload.setdefault("experiment", name)
    payload.setdefault("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
    payload.setdefault("notes", list(NOTES))
    with open(p, "w") as f:
        json.dump(payload, f, indent=2)
    if NOTES:
        with open(os.path.join(d, "notes.log"), "w") as f:
            f.write("\n".join(NOTES) + "\n")
    log(f"result written to {os.path.relpath(p, REPO_DIR)}")
    return p


def table(rows, headers):
    """Render a small ASCII table."""
    cols = len(headers)
    widths = [len(str(h)) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(r[i])))
    line = "  ".join("-" * w for w in widths)
    out = ["  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)), line]
    for r in rows:
        out.append("  ".join(str(r[i]).ljust(widths[i]) for i in range(cols)))
    return "\n".join(out)


def verdict(passed, msg):
    (ok if passed else fail)(msg)
    return passed


def exit_with(results):
    """Exit non-zero if any check failed."""
    bad = [k for k, v in results.items() if not v]
    if bad:
        fail(f"failed checks: {', '.join(bad)}")
        sys.exit(1)
    ok("all checks passed")
    sys.exit(0)
