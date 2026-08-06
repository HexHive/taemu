#!/usr/bin/env python3
"""E5 - Section VII: the opt-in shared memory mitigation for OP-TEE.

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
  3. checks that the mitigation actually closes the double-fetch window: the
     benchmark TA has two probe commands that read the same word of a memref
     twice per iteration while a normal-world thread flips it, one opted into
     shared memory and one not (optee_shm_patch/benchmark/bench_ta/bench_ta.c,
     bench_host/df_main.c). The opted-in command and the unpatched baseline
     must see disagreeing reads; the command that did not opt in must see none,
  4. regenerates the performance tables and the overhead plot from the
     benchmark results in optee_shm_patch/benchmark/results
     (optee_shm_patch/benchmark/harness/analyze.py),
  5. prints how to re-run the full QEMU benchmark.

Steps 3 and 4 re-analyse the shipped measurements; --run-qemu re-measures them
in QEMU, which needs a built OP-TEE tree ($OPTEE_DIR) and build.sh's output.

Output: ae/results/e5_mitigation/{mitigation,double_fetch}.{txt,csv,tex} plus
        shm_mitigation_overhead.png
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

# label -> (what the configuration is, whether a double fetch must be possible)
DF_CONFIGS = [
    ("baseline",     "unpatched libutee",              True),
    ("mitig_shared", "patched, opted in",              True),
    ("mitig_copied", "patched, not opted in",          False),
]


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


def read_df_csv(path):
    """label -> dict(differ, total, flips, size, iters, rounds)."""
    out = {}
    with open(path) as f:
        rows = [l.strip().split(",") for l in f if l.strip()]
    for r in rows:
        if len(r) < 10 or r[1] != "DFRESULT":
            continue
        out[r[0]] = dict(size=int(r[4]), iters=int(r[5]), rounds=int(r[6]),
                         differ=int(r[7]), total=int(r[8]), flips=int(r[9]))
    return out


# What a built OP-TEE QEMU-v8 tree has to provide for the probe: its own QEMU,
# the aarch64 toolchain and buildroot sysroot the TAs and the client are built
# with, and the boot images.
def optee_tree_usable(optee_dir):
    if not optee_dir or not os.path.isdir(optee_dir):
        return None
    need = {
        "qemu": os.path.join(optee_dir, "qemu", "build", "qemu-system-aarch64"),
        "toolchain": os.path.join(optee_dir, "toolchains", "aarch64", "bin",
                                  "aarch64-linux-gnu-gcc"),
        "sysroot": os.path.join(optee_dir, "out-br", "host",
                                "aarch64-buildroot-linux-gnu", "sysroot"),
        "optee_os": os.path.join(optee_dir, "optee_os", "lib", "libutee"),
        "boot images": os.path.join(optee_dir, "linux", "arch", "arm64", "boot", "Image"),
    }
    missing = [k for k, p in need.items() if not os.path.exists(p)]
    return missing or []


def build_bench(res_dir, optee_dir, out_dir):
    """optee_shm_patch/benchmark/build.sh: dev-kits, TAs, host binaries.

    The mitigation is entirely in libutee, so the patched build is a copy of
    $OPTEE_DIR/optee_os with optee_os.patch applied; the core image and
    therefore the whole boot chain is shared with the baseline.
    """
    ae.log("building the benchmark TAs against a patched and an unpatched libutee ...")
    p = subprocess.run(
        ["bash", os.path.join(ae.REPO_DIR, BENCH, "build.sh")],
        cwd=os.path.join(ae.REPO_DIR, BENCH),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3600,
        env=dict(os.environ, OPTEE_DIR=optee_dir, BASE_TREE=optee_dir, OUT=out_dir))
    open(os.path.join(res_dir, "build.log"), "wb").write(p.stdout or b"")
    if p.returncode != 0:
        ae.fail("building the benchmark failed, see build.log")
        print("\n".join((p.stdout or b"").decode("utf-8", "replace").splitlines()[-15:]))
    return p.returncode == 0


def run_qemu_df(res_dir, optee_dir, rebuild=True):
    """Build the two libutee variants and re-measure the probe in QEMU."""
    bench = os.path.join(ae.REPO_DIR, BENCH)
    out_dir = os.path.join(bench, "out")
    csv_path = os.path.join(res_dir, "df_test.csv")

    missing = optee_tree_usable(optee_dir)
    if missing is None:
        ae.fail("no OP-TEE tree: set $OPTEE_DIR to a built optee/ QEMU-v8 tree")
        return None
    if missing:
        ae.fail(f"{optee_dir} is not a built OP-TEE QEMU-v8 tree "
                f"(missing: {', '.join(missing)})")
        return None

    if rebuild or not os.path.exists(os.path.join(out_dir, "share", "optee_shm_dftest")):
        if not build_bench(res_dir, optee_dir, out_dir):
            return None

    ae.log("booting OP-TEE in QEMU for the double-fetch probe ...")
    p = subprocess.run(
        [sys.executable, os.path.join(bench, "harness", "driver.py"), "--df-only"],
        cwd=os.path.join(bench, "harness"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3600,
        env=dict(os.environ, OPTEE_DIR=optee_dir, BENCH_OUT=out_dir,
                 DF_CSV=csv_path))
    open(os.path.join(res_dir, "df_test_console.log"), "wb").write(p.stdout or b"")
    if p.returncode != 0 or not os.path.exists(csv_path):
        ae.fail("the probe run failed, see df_test_console.log")
        return None
    return csv_path


def double_fetch_check(res_dir, checks, optee_dir=None, run_qemu=None):
    """Does the mitigation actually close the double-fetch window?

    With a built OP-TEE tree this builds both libutee variants and measures it;
    without one it re-analyses the measurement shipped with the artifact.
    """
    measured_here = False
    csv_path = None
    if run_qemu is None:                # auto: measure it if we have the tree
        run_qemu = optee_tree_usable(optee_dir) == []
    if run_qemu:
        csv_path = run_qemu_df(res_dir, optee_dir)
        measured_here = csv_path is not None
        if not measured_here:
            checks["double-fetch probe measured"] = False
    if csv_path is None:
        csv_path = os.path.join(ae.REPO_DIR, BENCH, "results", "df_test.csv")
        ae.log(f"using the shipped measurement, "
               f"{os.path.relpath(csv_path, ae.REPO_DIR)}"
               + ("" if run_qemu else
                  " (set $OPTEE_DIR to a built OP-TEE QEMU-v8 tree to measure it)"))
    if not os.path.exists(csv_path):
        checks["double-fetch probe present"] = ae.verdict(False, f"missing {csv_path}")
        return {}
    meas = read_df_csv(csv_path)

    rows = []
    for label, what, racy in DF_CONFIGS:
        m = meas.get(label)
        if not m:
            checks[f"df probe: {label}"] = ae.verdict(False, f"no result for {label}")
            continue
        rate = 100.0 * m["differ"] / m["total"] if m["total"] else 0.0
        observed = m["differ"] > 0
        rows.append([label, what, m["total"], m["differ"], f"{rate:.1f}%",
                     "yes" if observed else "no",
                     "yes" if racy else "no"])
        checks[f"df probe {label}: double fetch "
               f"{'possible' if racy else 'impossible'}"] = ae.verdict(
            observed == racy,
            f"{label}: {m['differ']}/{m['total']} double fetches read two "
            f"different values")

    tables.write(res_dir, "double_fetch",
                 ["config", "libutee", "double fetches", "raced", "rate",
                  "observed", "expected"], rows,
                 title="E5 double-fetch probe (OP-TEE under QEMU"
                       + (", measured now)" if measured_here else ", shipped measurement)"),
                 caption="A normal-world thread races a memref while the TA "
                         "reads the same word twice. Without the opt-in the "
                         "mitigation makes the two reads always agree.",
                 label="tab:df_probe")
    return meas


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--optee-dir", default=os.environ.get("OPTEE_DIR"),
                    help="a checked-out optee_os tree to test the patch against")
    ap.add_argument("--run-qemu", dest="run_qemu", action="store_true", default=None,
                    help="build both libutee variants and measure the "
                         "double-fetch probe in QEMU (the default when "
                         "$OPTEE_DIR is a built OP-TEE QEMU-v8 tree)")
    ap.add_argument("--no-run-qemu", dest="run_qemu", action="store_false",
                    help="re-analyse the measurement shipped with the artifact")
    args = ap.parse_args()

    res_dir = os.path.join(ae.RESULTS_DIR, "e5_mitigation")
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
    # The patch is against optee_os, which sits inside the OP-TEE tree.
    optee_os = os.path.join(args.optee_dir or "", "optee_os")
    if args.optee_dir and os.path.isdir(optee_os):
        p = subprocess.run(
            ["git", "apply", "--check",
             os.path.join(ae.REPO_DIR, PATCH_DIR, "optee_os.patch")],
            cwd=optee_os, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode(errors="replace")
        open(os.path.join(res_dir, "git_apply.log"), "w").write(out)
        checks["patch applies to $OPTEE_DIR"] = ae.verdict(
            p.returncode == 0, f"optee_os.patch applies to {optee_os}")
        if p.returncode:
            ae.warn(out.strip()[:500])
    else:
        ae.warn("$OPTEE_DIR not set: patch not applied")

    # ------------------------------------------------ double fetch still possible?
    df = double_fetch_check(res_dir, checks, optee_dir=args.optee_dir,
                            run_qemu=args.run_qemu)

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
                 title="E5 mitigation patch",
                 caption="Size of the mitigation patch.",
                 label="tab:mitigation")

    ae.write_report("e5_mitigation", {"patches": rows, "double_fetch": df,
                                      "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
