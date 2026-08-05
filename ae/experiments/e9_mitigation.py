#!/usr/bin/env python3
"""E9 - Section VII: the opt-in shared memory mitigation for OP-TEE.

The mitigation extends the GlobalPlatform API with TEE_RegisterShm(): a TA
declares which memref parameters of which command really need zero-copy shared
memory. libutee passes those through unchanged and makes a TA-private copy of
every other memref, which closes the double-fetch window without touching the
TA code. The patch is optee_shm_patch/optee_os.patch (plus
optee_examples.patch for the example TAs).

What this experiment does:
  1. reports the size of the patch (paper: 140 lines of code),
  2. checks that the patch applies to an OP-TEE tree, if one is provided via
     $OPTEE_DIR (the OP-TEE source tree is not part of this artifact),
  3. regenerates the performance tables and the overhead plot from the
     benchmark results in optee_shm_patch/benchmark/results
     (optee_shm_patch/benchmark/harness/analyze.py),
  4. prints how to re-run the full QEMU benchmark.

Output: ae/results/e9_mitigation/{mitigation.txt,csv,tex,shm_mitigation_overhead.png}
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

PATCH_DIR = "optee_shm_patch"
BENCH = os.path.join(PATCH_DIR, "benchmark")


def patch_stats(path):
    added = removed = files = 0
    for line in open(path, errors="replace"):
        if line.startswith("+++ "):
            files += 1
        elif line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return files, added, removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--optee-dir", default=os.environ.get("OPTEE_DIR"),
                    help="a checked-out optee_os tree to test the patch against")
    args = ap.parse_args()

    res_dir = os.path.join(ae.RESULTS_DIR, "e9_mitigation")
    os.makedirs(res_dir, exist_ok=True)
    checks = {}

    # ------------------------------------------------------------ patch size
    rows = []
    for name in ("optee_os.patch", "optee_examples.patch"):
        p = os.path.join(ae.REPO_DIR, PATCH_DIR, name)
        if not os.path.exists(p):
            ae.fail(f"missing {name}")
            checks[f"{name} present"] = False
            continue
        files, added, removed = patch_stats(p)
        rows.append([name, files, added, removed])
        checks[f"{name} present"] = True
    if rows:
        core = next((r for r in rows if r[0] == "optee_os.patch"), None)
        if core:
            ae.log(f"optee_os.patch: {core[1]} files +{core[2]}/-{core[3]} lines")

    # ------------------------------------------------------- patch applies?
    if args.optee_dir and os.path.isdir(args.optee_dir):
        p = subprocess.run(
            ["git", "apply", "--check",
             os.path.join(ae.REPO_DIR, PATCH_DIR, "optee_os.patch")],
            cwd=args.optee_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode(errors="replace")
        open(os.path.join(res_dir, "git_apply.log"), "w").write(out)
        checks["patch applies to $OPTEE_DIR"] = ae.verdict(
            p.returncode == 0, f"optee_os.patch applies to {args.optee_dir}")
        if p.returncode:
            ae.warn(out.strip()[:500])
    else:
        ae.warn("$OPTEE_DIR not set: patch not applied")

    # -------------------------------------------------- benchmark re-analysis
    csv_path = os.path.join(ae.REPO_DIR, BENCH, "results", "results_v2.csv")
    if os.path.exists(csv_path):
        env = dict(os.environ, RESULTS_CSV=csv_path,
                   PLOT_OUT=os.path.join(res_dir, "shm_mitigation_overhead.png"),
                   BENCH_OUT=res_dir, MPLBACKEND="Agg")
        p = subprocess.run(
            [sys.executable, os.path.join(ae.REPO_DIR, BENCH, "harness", "analyze.py")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        out = p.stdout.decode(errors="replace")
        open(os.path.join(res_dir, "benchmark.txt"), "w").write(out)
        print(out)
        checks["benchmark re-analysed"] = ae.verdict(
            p.returncode == 0 and os.path.exists(
                os.path.join(res_dir, "shm_mitigation_overhead.png")),
            f"benchmark re-analysed -> {os.path.join(res_dir, 'shm_mitigation_overhead.png')}")
    else:
        checks["benchmark results present"] = ae.verdict(False, f"missing {csv_path}")

    tables.write(res_dir, "mitigation",
                 ["patch", "# files", "+ lines", "- lines"], rows,
                 title="E9 mitigation patch",
                 caption="Size of the mitigation patch.",
                 label="tab:mitigation")

    ae.write_report("e9_mitigation", {"patches": rows, "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
