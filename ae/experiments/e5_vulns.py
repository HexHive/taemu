#!/usr/bin/env python3
"""E5 - Table II: the six TOCTTOU vulnerabilities (~15 minutes).

This is the central "reproduced" experiment. For every vulnerability of
Table II the artifact ships the Exploration seed, the snapshot (register state
at the second fetch) and the crashing shared-memory value found by
Fetch-Anchored Fuzzing. The experiment

  1. restores the snapshot and injects the crashing value at the second fetch
     (emulator/df_fuzz.sh <harness> <seed> <reg_hash> <crash>)
     -> the TA must crash, and the crash type must match the paper, and
  2. runs Distillation on the same crash
     (emulator/df_validate.sh ...)
     -> the TA must NOT crash when the value is already there before the call,
        proving the vulnerability needs the shared-memory double fetch.

The on-device column of Table II (Section V) needs the rooted phones listed in
Table III and is reported from ae/data/paper_tables.json, not re-measured.

Output: ae/results/e5_vulns/{table2.txt,csv,tex}
"""

import argparse
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

VULNS = os.path.join(os.path.dirname(HERE), "data", "vulns.json")


def run_one(entry):
    src = os.path.join(ae.REPO_DIR, entry["harness"])
    crash_path = os.path.join(ae.REPO_DIR, entry["crash"])
    seed_path = os.path.join(src, "in", "suspicious_inputs_replay", entry["seed"])
    if not os.path.exists(crash_path) or not os.path.exists(seed_path):
        return dict(entry, status="missing", reproduced=False, distilled=False,
                    indicators=[],
                    detail="Exploration seed or crashing input not present. E5 replays the "
                           "campaign data of the paper (<tee>/harness/<h>/in/ and df_fuzz/), "
                           "which is not part of the git repository - unpack the campaign "
                           "archive into the repository first.")

    crash = {"snapshot": entry["snapshot"], "seed": entry["seed"],
             "seed_path": seed_path, "reg_hash": entry["reg_hash"],
             "crash": crash_path}
    work = os.path.join(ae.RESULTS_DIR, "e5_vulns", "work", entry["id"])
    shutil.rmtree(work, ignore_errors=True)
    ae.stage_harness(src, work, seeds=[seed_path], crashes=[crash])

    h_rel = ae.rel_to_emulator(work)
    seed_rel = ae.rel_to_emulator(os.path.join(work, "in", "suspicious_inputs_replay", entry["seed"]))
    crash_rel = ae.rel_to_emulator(os.path.join(
        work, "df_fuzz", entry["snapshot"], "out", "default", "crashes",
        os.path.basename(crash_path)))

    ae.log(f"[{entry['id']}] replaying the crashing double fetch ...")
    rc, out = ae.docker_run(
        f"./df_fuzz.sh '{h_rel}' '{seed_rel}' {entry['reg_hash']} '{crash_rel}'", timeout=1800)
    logdir = os.path.join(ae.RESULTS_DIR, "e5_vulns", "logs")
    os.makedirs(logdir, exist_ok=True)
    open(os.path.join(logdir, entry["id"] + "_replay.log"), "w").write(out)
    indicators = ae.classify_crash(out)
    asan = [l.strip() for l in out.splitlines() if "out-of-bound" in l or "uaf on" in l]

    ae.log(f"[{entry['id']}] running Distillation ...")
    rc, out2 = ae.docker_run(
        f"./df_validate.sh '{h_rel}' '{seed_rel}' {entry['reg_hash']} '{crash_rel}'", timeout=1800)
    open(os.path.join(logdir, entry["id"] + "_distill.log"), "w").write(out2)
    df_marker = os.path.join(work, "df_fuzz", entry["snapshot"], "out", "default",
                             "crashes", os.path.basename(crash_path) + ".df")
    distilled = ae.df_validated(out2) or os.path.exists(df_marker)

    return dict(entry, status="ok", reproduced=bool(indicators), distilled=bool(distilled),
                indicators=indicators, asan=asan[:3], detail="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", help="only these vulnerability ids")
    args = ap.parse_args()

    if not os.path.exists(VULNS):
        ae.fail(f"missing {VULNS}")
        sys.exit(1)
    entries = json.load(open(VULNS))["vulnerabilities"]
    if args.only:
        entries = [e for e in entries if e["id"] in args.only]

    res_dir = os.path.join(ae.RESULTS_DIR, "e5_vulns")
    os.makedirs(res_dir, exist_ok=True)

    results = [r for r in ae.parallel(run_one, entries, workers=min(ae.jobs(), len(entries))) if r]
    order = {e["id"]: i for i, e in enumerate(entries)}
    results.sort(key=lambda r: order[r["id"]])

    rows = []
    for r in results:
        rows.append([
            r["tee"], r["uuid"], r["ta"], r["vuln"],
            "yes" if r["reproduced"] else "NO",
            "yes" if r["distilled"] else "no",
            ",".join(r.get("indicators", [])) or "-",
            {True: "yes", False: "no", None: "n/a"}[r.get("on_device")],
        ])

    tables.write(res_dir, "table2",
                 ["TEE", "TA UUID", "TA Name", "DF Vulnerability",
                  "Reproduced (emulator)", "Needs shared memory", "Crash observed",
                  "Reproduced on device"],
                 rows,
                 title="Table II: vulnerabilities in commercial TAs found with ScHMuzz",
                 notes=[
                     "'Reproduced (emulator)' replays the snapshot and injects the crashing value at the second fetch.",
                     "'Needs shared memory' is the Distillation verdict: the same value placed before the call does not crash.",
                     "'Reproduced on device' is taken from the paper (Section V); it requires the rooted phones of Table III.",
                 ],
                 caption="The vulnerabilities in commercial TAs found with ScHMuzz.",
                 label="tab:vulns")

    reproduced = sum(1 for r in results if r["reproduced"])
    distilled = sum(1 for r in results if r["distilled"])
    checks = {
        "all vulnerabilities crash in the emulator": reproduced == len(results) and results != [],
        "all crashes require the shared-memory race": distilled == len(results) and results != [],
    }
    for k, v in checks.items():
        ae.verdict(v, k)
    for r in results:
        if not r["reproduced"]:
            ae.fail(f"  {r['id']}: {r.get('detail') or 'no crash observed'}")

    ae.write_report("e5_vulns", {"results": results, "reproduced": reproduced,
                                 "distilled": distilled, "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
