#!/usr/bin/env python3
"""E3 - Stage 3: Distillation (Section III-C).

Not every crash found by Fetch-Anchored Fuzzing needs the shared-memory race:
the fuzzed value may just as well be reachable through the first fetch. To tell
the two apart, Distillation replays each crash from the start of
TA_InvokeCommandEntryPoint with the crashing value placed in shared memory
*before* the TA runs, i.e. without any concurrent modification
(emulator/df_validate.sh, driven by eval/df_validate.py).

  * TA still crashes            -> not a double-fetch bug, discarded
  * TA runs to completion       -> the crash requires the double fetch, kept
                                   (a ".df" file is written next to the crash)

Paper: 330 crashes -> 62 crashes that are only triggerable with shared memory.

Sources:  --from faf       the crashes produced by E2 (ae_e2_* harnesses)
          --from campaign  the crashes shipped with the artifact (default)
Output:   ae/results/e3_distillation/{distillation.txt,csv,tex}
"""

import argparse
import glob
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

PREFIX = "ae_e3_"


def sources(source, selected):
    if source == "faf":
        found = sorted(glob.glob(os.path.join(ae.REPO_DIR, "*", "harness", "ae_e2_*")))
        if not found:
            ae.fail("no E2 working harnesses found - run ./ae.sh e2_faf first")
            sys.exit(1)
        return found
    hs = selected or ae.cfg("AE_SUBSET", "").split()
    return [os.path.join(ae.REPO_DIR, h) for h in hs]


def stage(src, crashes):
    tee_harness = os.path.dirname(src)
    name = os.path.basename(src)
    for p in ("ae_e2_", "ae_e1_"):
        if name.startswith(p):
            name = name[len(p):]
    work = os.path.join(tee_harness, PREFIX + name)
    shutil.rmtree(work, ignore_errors=True)
    seeds = {c["seed_path"] for c in crashes}
    ae.stage_harness(src, work, seeds=seeds, crashes=crashes)
    return work


def distill(job):
    work, crash, seconds = job
    seed_rel = ae.rel_to_emulator(os.path.join(
        work, "in", "suspicious_inputs_replay", crash["seed"]))
    crash_rel = ae.rel_to_emulator(os.path.join(
        work, "df_fuzz", crash["snapshot"], "out", "default", "crashes",
        os.path.basename(crash["crash"])))
    h_rel = ae.rel_to_emulator(work)
    rc, out = ae.docker_run(
        f"./df_validate.sh '{h_rel}' '{seed_rel}' {crash['reg_hash']} '{crash_rel}'",
        timeout=seconds)
    logs = os.path.join(ae.RESULTS_DIR, "e3_distillation", "logs")
    os.makedirs(logs, exist_ok=True)
    tag = f"{os.path.basename(work)}_{crash['reg_hash'][:12]}_{os.path.basename(crash['crash'])[:12]}"
    with open(os.path.join(logs, tag.replace("/", "_") + ".log"), "w") as f:
        f.write(out)
    kept = ae.df_validated(out) or os.path.exists(
        os.path.join(work, "df_fuzz", crash["snapshot"], "out", "default", "crashes",
                     os.path.basename(crash["crash"]) + ".df"))
    return {"harness": os.path.relpath(work, ae.REPO_DIR),
            "snapshot": crash["snapshot"],
            "crash": os.path.basename(crash["crash"]),
            "shared_memory_only": bool(kept),
            "crash_without_race": ae.classify_crash(out) if not kept else []}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="source", choices=["campaign", "faf"], default="campaign")
    ap.add_argument("--harnesses", nargs="*", default=None)
    ap.add_argument("--max-crashes", type=int, default=int(ae.cfg("AE_DISTILL_MAX", "40")),
                    help="upper bound on crashes per TA (0 = all)")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    res_dir = os.path.join(ae.RESULTS_DIR, "e3_distillation")
    os.makedirs(res_dir, exist_ok=True)

    jobs, per_ta = [], {}
    for src in sources(args.source, args.harnesses):
        if not os.path.exists(os.path.join(src, "harness.py")):
            continue
        crashes = [c for c in ae.harness_crashes(src) if c["replayable"]]
        skipped = len(ae.harness_crashes(src)) - len(crashes)
        if skipped:
            ae.warn(f"{os.path.relpath(src, ae.REPO_DIR)}: {skipped} crashes cannot be "
                    f"replayed (their Exploration seed is not part of the artifact)")
        if not crashes:
            continue
        chosen = crashes if args.max_crashes == 0 else crashes[: args.max_crashes]
        work = stage(src, chosen)
        for c in chosen:
            c2 = dict(c)
            jobs.append((work, c2, args.timeout))
        per_ta[os.path.relpath(src, ae.REPO_DIR)] = {
            "crashes_total": len(crashes), "crashes_distilled_input": len(chosen),
            "skipped_unreplayable": skipped,
            "workdir": os.path.relpath(work, ae.REPO_DIR)}

    if not jobs:
        ae.fail("no replayable crashes found")
        sys.exit(1)

    ae.log(f"distilling {len(jobs)} crashes ({ae.jobs()} in parallel)")
    results = [r for r in ae.parallel(distill, jobs) if r]

    rows = []
    kept_total = 0
    for ta, info in per_ta.items():
        mine = [r for r in results if r["harness"] == info["workdir"]]
        kept = sum(1 for r in mine if r["shared_memory_only"])
        kept_total += kept
        info["kept"] = kept
        info["checked"] = len(mine)
        rows.append([ta, info["crashes_total"], len(mine), kept, len(mine) - kept])
    rows.append(None)
    rows.append(["all", sum(i["crashes_total"] for i in per_ta.values()),
                 len(results), kept_total, len(results) - kept_total])

    tables.write(res_dir, "distillation",
                 ["TA (harness)", "# Crashes", "# checked",
                  "# Crashes Distilled (shared memory only)", "# discarded"],
                 rows,
                 title="E3 - Distillation",
                 notes=["A distilled crash is one that does NOT reproduce when the same value is "
                        "present from the start, i.e. it requires the attacker to win the race.",
                        "Paper (Table I): 330 crashes -> 62 distilled."],
                 caption="Distillation results (artifact evaluation run).",
                 label="tab:ae-distillation")

    checks = {
        "crashes replayed": len(results) > 0,
        "shared-memory-only crashes identified": kept_total > 0,
    }
    for k, v in checks.items():
        ae.verdict(v, k)

    ae.write_report("e3_distillation", {"source": args.source, "per_ta": per_ta,
                                        "crashes": results, "distilled": kept_total,
                                        "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
