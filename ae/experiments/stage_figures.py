#!/usr/bin/env python3
"""Stage 5 of e1_automatic_df_detection: Figures 4 and 5.

Both figures are produced by the artifact's own plotting pipeline,
eval/graphs/main.py; this experiment only drives it and collects its output.

  Figure 4 (--fuzz-mode ORG)  basic block coverage observed in Exploration over
                              campaign time, per TEE. The coverage of a queue
                              entry comes from replaying it (--regen-cov), the
                              denominator from the TA's CFG
                              (<tee>/tas/bbs/bb_<ta>.json, built by ghidra/).
  Figure 5 (--fuzz-mode DF)   basic blocks discovered per snapshot during
                              Fetch-Anchored Fuzzing, split into the blocks
                              executed before the second fetch, those also seen
                              by the seed / by Exploration, and those only
                              reached through the double fetch.

eval/graphs/main.py needs the coverage of the deduplicated Exploration inputs in
a separate directory; eval/graphs/bk_suspicious_inputs_covs.sh collects it, and
this experiment runs that first.

Output: ae/results/e1_automatic_df_detection/5_figures/{figure4,figure5}.png
        plus the pipeline's own per-TEE plots.
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae

GRAPHS = os.path.join(ae.REPO_DIR, "eval", "graphs")


def run(cmd, log, timeout=None):
    p = subprocess.run(cmd, cwd=GRAPHS, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout,
                       env=dict(os.environ, TAEMU_ROOT=ae.REPO_DIR,
                                TAEMU_IMAGE=ae.image(), MPLBACKEND="Agg"))
    out = (p.stdout or b"").decode("utf-8", "replace")
    open(log, "w").write(out)
    return p.returncode, out


def backup_suspicious_covs(res_dir):
    """eval/graphs/bk_suspicious_inputs_covs.sh: collect out/cov/run:id:*.cov."""
    back = os.path.join(res_dir, "ss_cov")
    shutil.rmtree(back, ignore_errors=True)
    os.makedirs(back, exist_ok=True)
    run(["bash", os.path.join(GRAPHS, "bk_suspicious_inputs_covs.sh"), ae.REPO_DIR, back],
        os.path.join(res_dir, "bk_suspicious_inputs_covs.log"), timeout=3600)
    d = os.path.join(back, "suspicious_inputs_covs")
    n = len(glob.glob(os.path.join(d, "**", "*.cov"), recursive=True))
    ae.log(f"seed coverage files: {n}")
    return d, n


def collect_outputs(res_dir):
    """Copy what eval/graphs/main.py produced into the result directory."""
    produced = {}
    for src, dst in (("org_control_flow_graph.png", "figure4.png"),
                     ("df_control_flow_graph.png", "figure5.png")):
        p = os.path.join(GRAPHS, src)
        if os.path.exists(p):
            shutil.copy(p, os.path.join(res_dir, dst))
            produced[dst] = os.path.getsize(p)
    out = os.path.join(GRAPHS, "multi_graph_out")
    if os.path.isdir(out) and os.listdir(out):
        dst = os.path.join(res_dir, "per_tee")
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(out, dst)
        produced["per_tee"] = len(os.listdir(dst))
    return produced


def regen_seed_cov(harnesses):
    """Replay the Exploration seed of every fuzzed snapshot.

    Figure 5 splits the blocks of a snapshot against the coverage of the seed
    that produced it, so that seed needs a drcov file. Seeds recorded after the
    deduplication pass (replaying inputs feeds the recorder again) have none,
    which made every snapshot derived from such a seed fail.
    """
    jobs = set()
    for h in harnesses:
        df_dir = os.path.join(h, "df_fuzz")
        if not os.path.isdir(df_dir):
            continue
        for snap in os.listdir(df_dir):
            seed = "_".join(snap.split("_")[:-1])
            seed_path = os.path.join(h, "in", "suspicious_inputs_replay", seed)
            cov = os.path.join(h, "out", "cov", seed + ".cov")
            if os.path.exists(seed_path) and not os.path.exists(cov):
                jobs.add((h, seed_path))
    jobs = sorted(jobs)
    if not jobs:
        return 0
    ae.log(f"replaying {len(jobs)} snapshot seeds")

    def replay(job):
        h, seed = job
        ae.docker_run(f"./fuzz.sh '{ae.rel_to_emulator(h)}' '{ae.rel_to_emulator(seed)}'",
                      timeout=600, env={"TAEMU_NO_RECORD": "1"})

    ae.parallel(replay, jobs)
    return len(jobs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fuzz-mode", choices=["ORG", "DF", "ALL"], default="ORG",
                    help="ORG = Figure 4, DF = Figure 5, ALL = both")
    ap.add_argument("--tees", nargs="*", default=None,
                    help="restrict to these TEEs (default: whatever has data)")
    ap.add_argument("--tas", nargs="*", default=None, help="restrict to these TAs")
    ap.add_argument("--regen-cov", action="store_true",
                    help="replay the queue entries to (re)generate their coverage; "
                         "needed after a fresh Exploration run")
    ap.add_argument("--max-timestamps", type=int,
                    default=int(ae.cfg("AE_EXPLORE_TIME", "86400")),
                    help="length of the x-axis in seconds (default: the Exploration "
                         "budget of this evaluation; the paper's campaign ran 86400 s)")
    ap.add_argument("--group-by", choices=["tee", "ta"], default="tee",
                    help="one panel per TEE (the paper's Figure 4) or one per TA")
    ap.add_argument("--show-rate", action="store_true",
                    help="plot the coverage rate instead of the basic block count")
    args = ap.parse_args()

    res_dir = ae.result_dir("5_figures")
    os.makedirs(res_dir, exist_ok=True)

    if args.regen_cov or args.fuzz_mode in ("DF", "ALL"):
        regen_seed_cov(sorted(glob.glob(os.path.join(ae.REPO_DIR, "*", "harness", "ae_e*_*"))))

    ss_dir, n = backup_suspicious_covs(res_dir)
    if n == 0:
        ae.fail("no coverage of deduplicated Exploration inputs found - run "
                "./ae.sh e1_exploration first")
        ae.write_report("5_figures", {"checks": {"figures generated": False}})
        sys.exit(1)

    # Figure 5 is built on top of the Exploration coverage (the ORG pass is what
    # fills accumulated_cov_bbs), so DF is always run as ALL.
    mode = "ALL" if args.fuzz_mode == "DF" else args.fuzz_mode
    cmd = [sys.executable, os.path.join(GRAPHS, "main.py"),
           "--path", ae.REPO_DIR, "--ss_cov_rdir", ss_dir,
           "--fuzz_mode", mode,
           "--max_timestamps", str(args.max_timestamps)]
    if args.regen_cov:
        cmd.append("--regen_coverage")
    if args.show_rate:
        cmd.append("--show_rate")
    if args.tees:
        cmd += ["--tees"] + args.tees
    if args.group_by == "tee":
        cmd += ["--org_group_field", "tee"]
    tas = args.tas
    if tas is None and glob.glob(os.path.join(ae.REPO_DIR, "*", "harness", "ae_e*_*")):
        # Restrict to the harnesses of this evaluation, so the figure describes
        # the campaign that was just run and not a mixture with the shipped one.
        tas = ["ae_e"]
    if tas:
        cmd += ["--tas"] + tas

    ae.log(f"eval/graphs/main.py mode={mode}"
           f"{' regen_coverage' if args.regen_cov else ''}")
    rc, out = run(cmd, os.path.join(res_dir, "graphs.log"), timeout=6 * 3600)
    if rc != 0:
        ae.fail("eval/graphs/main.py failed:")
        print("\n".join(out.splitlines()[-25:]))

    produced = collect_outputs(res_dir)
    checks = {}
    if args.fuzz_mode in ("ORG", "ALL"):
        checks["figure 4 generated"] = "figure4.png" in produced
    if args.fuzz_mode in ("DF", "ALL"):
        checks["figure 5 generated"] = "figure5.png" in produced
    for k, v in checks.items():
        ae.verdict(v, k)
    for f in ("figure4.png", "figure5.png"):
        p = os.path.join(res_dir, f)
        if f in produced:
            print(f"  {os.path.relpath(p, ae.REPO_DIR)}")
    if "per_tee" in produced:
        print(f"  {os.path.relpath(os.path.join(res_dir, 'per_tee'), ae.REPO_DIR)}/ "
              f"({produced['per_tee']} files)")

    ae.write_report("5_figures", {"fuzz_mode": args.fuzz_mode,
                                   "suspicious_cov_files": n,
                                   "produced": produced, "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
