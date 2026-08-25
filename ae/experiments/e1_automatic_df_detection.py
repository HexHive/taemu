#!/usr/bin/env python3
"""E1 - Automatic double-fetch detection: the pipeline of Section III.

One campaign, five stages, run in order because each consumes what the previous
one produced:

  1 exploration   fuzz every TA of $AE_SUBSET while tracing accesses to the
                  shared memref buffers, deduplicate the recordings and
                  annotate the overlapped fetches -> snapshots
  2 faf           restore each snapshot and fuzz the value read at the second
                  fetch -> crashes
  3 distillation  replay each crash without the race and keep only the ones
                  that need it -> .df crashes
  4 table1        Table I of the campaign just produced
  5 figures       Figure 4 (coverage of Exploration) and Figure 5 (blocks
                  discovered per snapshot during Fetch-Anchored Fuzzing)

Output: Table I and the two figures in ae/results/e1_automatic_df_detection/,
        each stage's own tables, logs and result.json in <n>_<stage>/ below it.

  ./ae.sh e1_automatic_df_detection                    # the whole pipeline
  ./ae.sh e1_automatic_df_detection --only table1 figures   # re-render only
  ./ae.sh e1_automatic_df_detection --from faf         # continue a campaign
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

NAME = "e1_automatic_df_detection"

# (stage, script, result subdirectory, fixed arguments)
STAGES = [
    ("exploration",  "stage_exploration.py",  "1_exploration",  []),
    ("faf",          "stage_faf.py",          "2_faf",          ["--from", "exploration"]),
    ("distillation", "stage_distillation.py", "3_distillation", ["--from", "faf"]),
    ("table1",       "stage_table1.py",       "4_table1",       ["--source", "ae"]),
    ("figures",      "stage_figures.py",      "5_figures",      ["--fuzz-mode", "ALL",
                                                                 "--regen-cov",
                                                                 "--show-rate"]),
]

# What each stage contributes to the merged result directory.
DELIVERABLES = {
    "4_table1":  [("table1_ae.txt", "table1.txt"), ("table1_ae.csv", "table1.csv"),
                  ("table1_ae.tex", "table1.tex")],
    "5_figures": [("figure4.png", "figure4.png"), ("figure5.png", "figure5.png")],
}


def run_stage(script, args):
    """Run one stage as a subprocess, streaming its output."""
    env = dict(os.environ, AE_STAGE_OF=NAME, TAEMU_ROOT=ae.REPO_DIR)
    p = subprocess.run([sys.executable, os.path.join(HERE, script)] + args, env=env)
    return p.returncode


def stage_report(sub):
    p = os.path.join(ae.RESULTS_DIR, NAME, sub, "result.json")
    if not os.path.exists(p):
        return {}
    try:
        return json.load(open(p))
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+", choices=[s[0] for s in STAGES],
                    help="run only these stages (they still need the output of "
                         "the ones before them)")
    ap.add_argument("--from", dest="start", choices=[s[0] for s in STAGES],
                    help="start at this stage and run the rest")
    ap.add_argument("--time", type=int, default=None,
                    help="Exploration budget per TA in seconds "
                         f"(default: AE_EXPLORE_TIME={ae.cfg('AE_EXPLORE_TIME', '1800')})")
    ap.add_argument("--reps", type=int, default=None,
                    help="Exploration repetitions per TA "
                         f"(default: AE_EXPLORE_REPS={ae.cfg('AE_EXPLORE_REPS', '1')})")
    ap.add_argument("--harnesses", nargs="*", default=None,
                    help="harness directories, or 'all' (default: $AE_SUBSET)")
    ap.add_argument("--keep", action="store_true",
                    help="continue a previous run instead of starting over")
    args = ap.parse_args()

    selected = [s[0] for s in STAGES]
    if args.start:
        selected = selected[selected.index(args.start):]
    if args.only:
        selected = [s for s in selected if s in args.only]

    res_dir = ae.result_dir(NAME)
    checks = {}
    rcs = {}

    for stage, script, sub, fixed in STAGES:
        if stage not in selected:
            continue
        extra = list(fixed)
        if stage == "exploration":
            if args.time is not None:
                extra += ["--time", str(args.time)]
            if args.reps is not None:
                extra += ["--reps", str(args.reps)]
            if args.harnesses:
                extra += ["--harnesses"] + args.harnesses
            if args.keep:
                extra += ["--keep"]
        if stage in ("faf", "distillation") and args.harnesses:
            extra += ["--harnesses"] + args.harnesses
        if stage == "figures":
            budget = args.time if args.time is not None \
                else int(ae.cfg("AE_EXPLORE_TIME", "1800"))
            extra += ["--max-timestamps", str(budget)]

        ae.banner(f"Stage {sub[0]} - {stage}")
        rcs[stage] = run_stage(script, extra)
        rep = stage_report(sub)
        for k, v in (rep.get("checks") or {}).items():
            checks[f"{stage}: {k}"] = bool(v)
        if not rep:
            checks[f"{stage}: completed"] = False

        for src, dst in DELIVERABLES.get(sub, []):
            p = os.path.join(ae.RESULTS_DIR, NAME, sub, src)
            if os.path.exists(p):
                shutil.copy(p, os.path.join(res_dir, dst))

    # ------------------------------------------------------------- deliverables
    table1 = os.path.join(res_dir, "table1.txt")
    if os.path.exists(table1):
        print()
        print(open(table1).read())
    for f in ("figure4.png", "figure5.png"):
        p = os.path.join(res_dir, f)
        if os.path.exists(p):
            print(f"  {os.path.relpath(p, ae.REPO_DIR)}")

    ae.write_report(NAME, {"stages": {s: rcs.get(s) for s in selected},
                           "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
