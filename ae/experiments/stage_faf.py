#!/usr/bin/env python3
"""Stage 2 of e1_automatic_df_detection: Fetch-Anchored Fuzzing (Sec. III-B).

For every snapshot found by Exploration, the emulator restores the TA state
right before the second fetch and fuzzes *the value read from shared memory*
(emulator/df_fuzz.sh). Crashes are memory-safety violations that a malicious
normal-world app could trigger by winning the race.

Sources of snapshots:
  --from exploration  the snapshots produced by stage 1 (ae_e1_* harnesses)
  --from campaign     the snapshots shipped with the artifact (default), i.e.
                      the ones of the paper's campaign; only snapshots whose
                      Exploration seed is still present can be restored

Budget:  AE_FAF_TIME seconds per snapshot (paper: 900), at most
         AE_FAF_MAX_SNAPSHOTS snapshots per TA.
Output:  ae/results/e2_faf/{faf.txt,csv,tex}
"""

import argparse
import glob
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

PREFIX = "ae_e2_"


def source_harnesses(source, selected):
    if source == "exploration":
        found = sorted(glob.glob(os.path.join(ae.REPO_DIR, "*", "harness", "ae_e1_*")))
        if not found:
            ae.fail("no E1 working harnesses found - run ./ae.sh e1_exploration first")
            sys.exit(1)
        return found
    return ae.resolve_harnesses(selected)


def stage(src, snaps):
    """Where to run Fetch-Anchored Fuzzing for this harness.

    Snapshots that came from our own Exploration run (ae_e1_*) are fuzzed *in
    place*: the plotting pipeline links Exploration and Fetch-Anchored Fuzzing
    by harness directory (eval/graphs/collect_cov.py:linking), so out/ and
    df_fuzz/ of one campaign have to live in the same harness. Only the
    campaign data shipped with the artifact is copied, so it stays untouched.
    """
    if os.path.basename(src).startswith("ae_e1_"):
        return src

    tee_harness = os.path.dirname(src)
    name = os.path.basename(src)
    if name.startswith("ae_e1_"):
        name = name[len("ae_e1_"):]
    work = os.path.join(tee_harness, PREFIX + name)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "in", "suspicious_inputs_replay"), exist_ok=True)
    shutil.copy(os.path.join(src, "harness.py"), work)
    ta = ae.ta_of(src)
    os.symlink(os.path.relpath(os.path.realpath(ta), work),
               os.path.join(work, os.path.basename(ta)))
    js = os.path.realpath(ta)[: -len(".ta")] + ".json"
    if os.path.exists(js):
        os.symlink(os.path.relpath(js, work), os.path.join(work, os.path.basename(js)))
    for s in snaps:
        for suffix in ("", ".meta"):
            p = s["seed_path"] + suffix
            if os.path.exists(p):
                dst = os.path.join(work, "in", "suspicious_inputs_replay",
                                   os.path.basename(p))
                if not os.path.exists(dst):
                    shutil.copy(p, dst)
    return work


def fuzz_snapshot(job):
    work, snap, seconds = job
    seed_rel = ae.rel_to_emulator(os.path.join(
        work, "in", "suspicious_inputs_replay", snap["seed"]))
    h_rel = ae.rel_to_emulator(work)
    rc, out = ae.docker_run(
        f"./df_fuzz.sh '{h_rel}' '{seed_rel}' {snap['reg_hash']}",
        timeout=seconds + 900, env={"FUZZTIME": str(seconds)})
    logs = os.path.join(ae.result_dir("2_faf"), "logs")
    os.makedirs(logs, exist_ok=True)
    with open(os.path.join(logs, f"{os.path.basename(work)}_{snap['reg_hash'][:12]}.log"), "w") as f:
        f.write(out)
    return {"snapshot": snap["name"],
            "reproduced": not ae.df_not_reproduced(out),
            "crash_indicators": ae.classify_crash(out)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="source", choices=["campaign", "exploration"],
                    default="campaign")
    ap.add_argument("--harnesses", nargs="*", default=None)
    ap.add_argument("--time", type=int, default=int(ae.cfg("AE_FAF_TIME", "180")))
    ap.add_argument("--max-snapshots", type=int,
                    default=int(ae.cfg("AE_FAF_MAX_SNAPSHOTS", "25")))
    args = ap.parse_args()

    res_dir = ae.result_dir("2_faf")
    os.makedirs(res_dir, exist_ok=True)

    rows, per_ta, jobs = [], {}, []
    works = {}
    for src in source_harnesses(args.source, args.harnesses):
        if not os.path.exists(os.path.join(src, "harness.py")):
            continue
        snaps = ae.harness_snapshots(src)
        uniq, seen = [], set()
        for s in snaps:
            if s["name"] not in seen:
                seen.add(s["name"])
                uniq.append(s)
        if not uniq:
            ae.warn(f"{os.path.relpath(src, ae.REPO_DIR)}: no restorable snapshots")
            continue
        chosen = uniq[: args.max_snapshots]
        work = stage(src, chosen)
        works[src] = work
        for s in chosen:
            jobs.append((work, s, args.time))
        per_ta[os.path.relpath(src, ae.REPO_DIR)] = {
            "snapshots_total": len(uniq), "snapshots_fuzzed": len(chosen),
            "workdir": os.path.relpath(work, ae.REPO_DIR)}

    if not jobs:
        ae.fail("no snapshots to fuzz")
        sys.exit(1)

    ae.log(f"snapshots={len(jobs)} time={args.time}s jobs={ae.jobs()} "
           f"eta={len(jobs) * args.time / max(ae.jobs(), 1) / 60:.0f}min")
    results = ae.parallel(fuzz_snapshot, jobs)

    total_crashes = 0
    for src, info in per_ta.items():
        work = os.path.join(ae.REPO_DIR, info["workdir"])
        crashes = ae.harness_crashes(work)
        info["crashes"] = len(crashes)
        info["snapshots_with_crash"] = len({c["snapshot"] for c in crashes})
        total_crashes += len(crashes)
        rows.append([src, info["snapshots_total"], info["snapshots_fuzzed"],
                     info["snapshots_with_crash"], info["crashes"]])
    rows.append(None)
    rows.append(["all", sum(i["snapshots_total"] for i in per_ta.values()),
                 sum(i["snapshots_fuzzed"] for i in per_ta.values()),
                 sum(i["snapshots_with_crash"] for i in per_ta.values()), total_crashes])

    tables.write(res_dir, "faf",
                 ["TA (harness)", "# snapshots", "# fuzzed", "# crashing snapshots", "# Crashes"],
                 rows,
                 title="E2 fetch-anchored fuzzing",
                 caption="Fetch-Anchored Fuzzing results (artifact evaluation run).",
                 label="tab:ae-faf")

    reproduced = sum(1 for r in results if r and r["reproduced"])
    # Finding a crash is budget-dependent: the paper fuzzed every snapshot for
    # 15 minutes and only 330 of 17,232 snapshots ever crashed. The capability
    # under test here is that a snapshot can be restored and its second fetch
    # fuzzed; whether a crash appears in a short AE run is reported, not asserted.
    checks = {"snapshots restored and fuzzed": reproduced > 0}
    for k, v in checks.items():
        ae.verdict(v, k)
    ae.log(f"double fetch reached: {reproduced}/{len(jobs)} snapshots")
    ae.log(f"crashes: {total_crashes}")

    ae.write_report("2_faf", {"budget_seconds": args.time, "source": args.source,
                               "per_ta": per_ta, "snapshots": results,
                               "total_crashes": total_crashes, "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
