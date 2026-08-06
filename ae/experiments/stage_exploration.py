#!/usr/bin/env python3
"""Stage 1 of e1_automatic_df_detection: Exploration (Section III-A).

Fuzzes TAs with the emulator (emulator/fuzz.sh) while tracing accesses to the
shared memref buffers, deduplicates the recorded traces (eval/deduplicate.py),
annotates the overlapped fetches (eval/annotate_fetches.py) and reports, per
TA, how many overlapped fetches were found and how many snapshots they merge
into. Those snapshots are the input of Fetch-Anchored Fuzzing (stage 2).

Claim under test: "ScHMuzz detected overlapped fetches in 23 TAs (75% of the
fuzzed TAs)" - at AE scale, on the TA subset of ae/config.env, we expect
overlapped fetches in the TAs that the paper reports them for.

Budget:  AE_EXPLORE_TIME seconds x AE_EXPLORE_REPS repetitions per TA
         (paper: 86400 s x 5).  Default: 300 s x 1 per TA.
Output:  ae/results/e1_automatic_df_detection/1_exploration/
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

PREFIX = "ae_e1_"


def stage(harness, keep):
    """Create <tee>/harness/ae_e1_<name>: a pristine copy of the harness.

    Running in-place would overwrite the campaign data shipped with the
    artifact, so Exploration always starts from an empty working harness. The
    directory has to live next to the original one because the deduplication
    and orchestration scripts (and swarm) discover work by the
    <tee>/harness/<name> layout.
    """
    tee_harness = os.path.dirname(harness)
    work = os.path.join(tee_harness, PREFIX + os.path.basename(harness))
    if os.path.exists(work) and not keep:
        shutil.rmtree(work, ignore_errors=True)
    if not os.path.exists(work):
        os.makedirs(os.path.join(work, "in"), exist_ok=True)
        shutil.copy(os.path.join(harness, "harness.py"), work)
        ta = ae.ta_of(harness)
        os.symlink(os.path.relpath(os.path.realpath(ta), work),
                   os.path.join(work, os.path.basename(ta)))
        js = os.path.realpath(ta)[: -len(".ta")] + ".json"
        if os.path.exists(js):
            os.symlink(os.path.relpath(js, work),
                       os.path.join(work, os.path.basename(js)))
        seeds = os.path.join(harness, "in")
        for f in sorted(os.listdir(seeds)) if os.path.isdir(seeds) else []:
            src = os.path.join(seeds, f)
            if os.path.isfile(src):                      # only the plain seeds
                shutil.copy(src, os.path.join(work, "in", f))
    return work


def explore(job):
    work, seconds, rep = job
    rel = ae.rel_to_emulator(work)
    ae.log(f"exploring {os.path.basename(work)} (repetition {rep + 1}, {seconds}s)")
    rc, out = ae.docker_run(f"./fuzz.sh '{rel}'", timeout=seconds + 900,
                            env={"FUZZTIME": str(seconds)})
    logs = os.path.join(ae.result_dir("1_exploration"), "logs")
    os.makedirs(logs, exist_ok=True)
    with open(os.path.join(logs, f"{os.path.basename(work)}_rep{rep}.log"), "w") as f:
        f.write(out)
    return rc


def deduplicate(paths):
    """eval/deduplicate.py: replay every recorded input and drop the ones with
    identical coverage; this is what fills in/suspicious_inputs_replay."""
    # Deduplication replays every recorded input in a container, so a TA with
    # thousands of recordings would dominate the AE runtime. AE_DEDUP_LIMIT
    # bounds how many recordings per TA are considered (0 = all, as in the paper).
    limit = int(ae.cfg("AE_DEDUP_LIMIT", "150"))
    logs = os.path.join(ae.result_dir("1_exploration"), "logs")
    os.makedirs(logs, exist_ok=True)

    # Harnesses are deduplicated concurrently, each with its own set of worker
    # containers (TAEMU_EMU_PREFIX) and its share of the pool. Without the
    # prefix all runs would fight over the same emu_N container names, which is
    # why this used to be one harness at a time.
    total = ae.jobs()
    lanes = max(1, min(len(paths), total))
    per_lane = max(1, total // lanes)
    ae.log(f"dedup: {len(paths)} harnesses, {lanes} lanes x {per_lane} containers")

    def dedup_one(job):
        idx, p = job
        cmd = [sys.executable, os.path.join(ae.REPO_DIR, "eval", "deduplicate.py"),
               "--path", p, "--mode", "coverage", "--enable-del",
               "--num-replay-containers", str(per_lane)]
        if limit:
            cmd += ["--per-harness-limit", str(limit)]
        proc = subprocess.run(
            cmd,
            cwd=os.path.join(ae.REPO_DIR, "eval"), input=b"y\ny\n",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=dict(os.environ, TAEMU_ROOT=ae.REPO_DIR,
                     TAEMU_EMU_PREFIX=f"emu{idx % lanes}_"))
        with open(os.path.join(logs, f"dedup_{os.path.basename(p)}.log"), "wb") as f:
            f.write(proc.stdout or b"")

    ae.parallel(dedup_one, list(enumerate(paths)), workers=lanes)


def annotate(paths):
    """eval/annotate_fetches.py: mark every read that revisits an already
    accessed shared-memory range as a second (overlapped) fetch."""
    def annotate_one(p):
        subprocess.run(
            [sys.executable, os.path.join(ae.REPO_DIR, "eval", "annotate_fetches.py"),
             "--path", p, "--dirs", "both"],
            cwd=os.path.join(ae.REPO_DIR, "eval"),
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            env=dict(os.environ, TAEMU_ROOT=ae.REPO_DIR))

    ae.parallel(annotate_one, paths)


def count(work):
    """(recorded inputs, overlapped fetches, snapshots) of one harness.

    Deduplication moves a seed from in/suspicious_inputs to
    in/suspicious_inputs_replay and deletes the redundant ones, so both
    directories have to be counted, with a seed present in both counted once.
    Counting the fetches in one directory and the snapshots in the other is what
    made '# Overl. Fetches merged' come out larger than '# Overl. Fetches',
    which is impossible: merging can only ever reduce the number of fetches.
    """
    inputs = 0
    fetches = 0
    seen = set()
    for sub in ("suspicious_inputs_replay", "suspicious_inputs"):
        d = os.path.join(work, "in", sub)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".meta") or f in seen:
                continue
            seen.add(f)
            inputs += 1
            fetches += ae.overlapped_fetches(os.path.join(d, f))
    # Snapshots are enumerated from the deduplicated seeds only: those are the
    # ones Fetch-Anchored Fuzzing can restore.
    snaps = ae.harness_snapshots(work)
    return inputs, fetches, len({s["name"] for s in snaps})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harnesses", nargs="*", default=None,
                    help="harness directories, or 'all' for every TA of the campaign "
                         "(default: $AE_SUBSET)")
    ap.add_argument("--time", type=int, default=int(ae.cfg("AE_EXPLORE_TIME", "300")))
    ap.add_argument("--reps", type=int, default=int(ae.cfg("AE_EXPLORE_REPS", "1")))
    ap.add_argument("--keep", action="store_true", help="continue a previous run")
    ap.add_argument("--skip-fuzzing", action="store_true",
                    help="only re-run deduplication/annotation and the report")
    ap.add_argument("--report-only", action="store_true",
                    help="only re-render the table from the existing working harnesses")
    args = ap.parse_args()

    harnesses = ae.resolve_harnesses(args.harnesses)
    if not harnesses:
        ae.fail("no harnesses selected (set AE_SUBSET, or pass --harnesses / "
                "--harnesses all)")
        sys.exit(1)

    res_dir = ae.result_dir("1_exploration")
    os.makedirs(res_dir, exist_ok=True)
    kinibi = sum(1 for h in harnesses
                 if os.path.basename(h) in ("0801_fuzz", "abcd_fuzz", "df1e_fuzz"))
    tas = len(harnesses) + kinibi   # a Kinibi TA counts for Kinibi and Beanpod
    ae.log(f"harnesses={len(harnesses)} tas={tas} time={args.time}s reps={args.reps} "
           f"jobs={ae.jobs()} eta={args.time * args.reps * ((len(harnesses) + ae.jobs() - 1) // ae.jobs()) / 3600:.1f}h")

    works = ([os.path.join(os.path.dirname(h), PREFIX + os.path.basename(h))
              for h in harnesses] if args.report_only
             else [stage(h, args.keep) for h in harnesses])

    if not args.skip_fuzzing and not args.report_only:
        jobs = [(w, args.time, rep) for rep in range(args.reps) for w in works]
        ae.parallel(explore, jobs)

    if not args.report_only:
        deduplicate(works)
        annotate(works)

    rows = []
    per_ta = {}
    total_fetches = total_snaps = with_fetches = 0
    for h, w in zip(harnesses, works):
        inputs, fetches, snaps = count(w)
        name = os.path.relpath(h, ae.REPO_DIR)
        per_ta[name] = {"recorded_inputs": inputs, "overlapped_fetches": fetches,
                        "snapshots": snaps, "workdir": os.path.relpath(w, ae.REPO_DIR)}
        rows.append([name, inputs, fetches, snaps, "yes" if fetches or snaps else "no"])
        total_fetches += fetches
        total_snaps += snaps
        with_fetches += 1 if (fetches or snaps) else 0
    rows.append(None)
    rows.append(["all", "", total_fetches, total_snaps, f"{with_fetches}/{len(harnesses)}"])

    tables.write(res_dir, "exploration",
                 ["TA (harness)", "# recorded inputs", "# Overl. Fetches",
                  "# Overl. Fetches merged", "overlapped fetches?"], rows,
                 title="E1 exploration",
                 caption="Exploration results (artifact evaluation run).",
                 label="tab:ae-exploration")

    checks = {
        "exploration produced recordings": any(v["recorded_inputs"] for v in per_ta.values()),
        "overlapped fetches found": with_fetches > 0,
        "snapshots for E2 produced": total_snaps > 0,
        # merging contiguous second fetches can only reduce their number
        "snapshots <= overlapped fetches": total_snaps <= total_fetches,
    }
    for k, v in checks.items():
        ae.verdict(v, k)

    ae.write_report("1_exploration", {
        "budget_seconds": args.time, "repetitions": args.reps,
        "per_ta": per_ta, "tas_with_overlapped_fetches": with_fetches,
        "total_overlapped_fetches": total_fetches, "total_snapshots": total_snaps,
        "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
