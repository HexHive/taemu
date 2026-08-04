#!/usr/bin/env python3
"""E8 - Figures 4 and 5.

Figure 4  Basic block coverage observed in Exploration, per TEE.
          x: campaign time, y: percentage of the basic blocks that are
          reachable from TA_InvokeCommandEntryPoint (Section IV: 15-30%).
          Numerator:   the drcov files of the Exploration queue seeds
                       (<harness>/out/cov/*.cov), accumulated in the order in
                       which AFL saved the seeds.
          Denominator: the basic blocks reachable from
                       TA_InvokeCommandEntryPoint in the TA's CFG
                       (<tee>/tas/bbs/bb_<ta>.json, produced by ghidra/).

Figure 5  Basic blocks discovered during Fetch-Anchored Fuzzing, per snapshot,
          split into
            executed before the second fetch (blue),
            also covered by the seed that triggered the double fetch (orange),
            also covered during Exploration (green),
            only covered during Fetch-Anchored Fuzzing (red).
          This needs coverage for the Fetch-Anchored Fuzzing queue, which is
          only written when the queue entries are replayed; use --regen-faf-cov
          to replay them (bounded by --max-snapshots).

Output: ae/results/e8_figures/{figure4.pdf,figure4.png,figure5.pdf,figure5.png}
        plus the underlying numbers as .csv
"""

import argparse
import csv
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import aelib as ae
import cfg as cfglib
import drcov

TEES = ["teegris", "qsee", "kinibi", "mitee", "beanpod"]
TEE_LABEL = {"teegris": "TEEGris", "qsee": "QSEE", "kinibi": "Kinibi",
             "mitee": "MiTEE", "beanpod": "Beanpod"}
KINIBI_HARNESSES = {"0801_fuzz", "abcd_fuzz", "df1e_fuzz"}


def tee_of(harness):
    return os.path.relpath(harness, ae.REPO_DIR).split(os.sep)[0]


def harness_curve(harness):
    """(times, cumulative unique BBs, reachable BBs) for one Exploration run."""
    cov_dir = os.path.join(harness, "out", "cov")
    ta = ae.ta_of(harness)
    if not os.path.isdir(cov_dir) or not ta:
        return None
    tee = tee_of(harness)
    covs = []
    for f in sorted(os.listdir(cov_dir)):
        if not f.endswith(".cov"):
            continue
        covs.append((drcov.seed_time(f), os.path.join(cov_dir, f)))
    if not covs:
        return None
    covs.sort()
    # Only basic blocks that are reachable from TA_InvokeCommandEntryPoint are
    # counted: a TA also executes its create/open-session entry points and
    # library code, which is not part of the attacker-reachable surface the
    # figure is about.
    reachable = cfglib.reachable_bb_set(ta)
    seen = set()
    times, values = [], []
    for t, path in covs:
        seen |= drcov.parse(path, tee) & reachable
        times.append(t)
        values.append(len(seen))
    return times, values, len(reachable)


def figure4(res_dir, harnesses):
    per_tee = {t: [] for t in TEES}
    raw = {}
    for h in harnesses:
        tee = tee_of(h)
        name = os.path.basename(h)
        if tee == "beanpod" and name in KINIBI_HARNESSES:
            tee = "kinibi"            # Kinibi TAs are emulated on the Beanpod runtime
        if tee not in per_tee:
            continue
        curve = harness_curve(h)
        if not curve:
            continue
        times, values, reachable = curve
        if not reachable:
            ae.warn(f"{os.path.relpath(h, ae.REPO_DIR)}: no CFG data "
                    f"(<tee>/tas/bbs/bb_*.json), skipped in Figure 4")
            continue
        pct = [100.0 * v / reachable for v in values]
        per_tee[tee].append((times, pct))
        raw[os.path.relpath(h, ae.REPO_DIR)] = {
            "reachable_bbs": reachable, "final_bbs": values[-1],
            "final_percent": round(pct[-1], 2), "duration_s": times[-1]}

    used = [t for t in TEES if per_tee[t]]
    if not used:
        ae.warn("no Exploration coverage data found - run E2 first, or check <harness>/out/cov")
        return raw, False

    fig, axes = plt.subplots(1, len(used), figsize=(3.0 * len(used), 2.6), sharey=True)
    if len(used) == 1:
        axes = [axes]
    for ax, tee in zip(axes, used):
        end = max(max(t) for t, _ in per_tee[tee]) or 1
        grid = [end * i / 100.0 for i in range(101)]
        curves = []
        for times, pct in per_tee[tee]:
            cur, j, out = 0.0, 0, []
            for g in grid:
                while j < len(times) and times[j] <= g:
                    cur = pct[j]
                    j += 1
                out.append(cur)
            curves.append(out)
        mean = [sum(c[i] for c in curves) / len(curves) for i in range(len(grid))]
        lo = [min(c[i] for c in curves) for i in range(len(grid))]
        hi = [max(c[i] for c in curves) for i in range(len(grid))]
        ax.plot(grid, mean, color="orange")
        ax.fill_between(grid, lo, hi, color="orange", alpha=0.3)
        ax.set_title(TEE_LABEL[tee], fontsize=10)
        ax.set_ylim(0, 100)
        ax.set_xlim(0, end)
        ax.set_xticks([])
    axes[0].set_ylabel("Basic Block Coverage %")
    fig.supxlabel(f"Time: 0 to {int(max(max(t) for c in per_tee.values() for t, _ in c) / 60)} min",
                  fontsize=9)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(res_dir, f"figure4.{ext}"), dpi=200)
    plt.close(fig)

    with open(os.path.join(res_dir, "figure4.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["harness", "reachable_bbs", "covered_bbs", "coverage_percent", "duration_s"])
        for k, v in sorted(raw.items()):
            w.writerow([k, v["reachable_bbs"], v["final_bbs"], v["final_percent"], v["duration_s"]])
    ae.ok(f"Figure 4 written ({len(raw)} TAs, {len(used)} TEEs)")
    return raw, True


def regen_faf_cov(harness, snapshot, limit):
    """Replay the Fetch-Anchored Fuzzing queue of one snapshot to get coverage."""
    qdir = os.path.join(harness, "df_fuzz", snapshot, "out", "default", "queue")
    if not os.path.isdir(qdir):
        return 0
    seed = "_".join(snapshot.split("_")[:-1])
    reg_hash = snapshot.split("_")[-1]
    seed_path = os.path.join(harness, "in", "suspicious_inputs_replay", seed)
    if not os.path.exists(seed_path):
        return 0
    h_rel = ae.rel_to_emulator(harness)
    seed_rel = ae.rel_to_emulator(seed_path)
    done = 0
    for q in sorted(os.listdir(qdir))[:limit]:
        q_rel = ae.rel_to_emulator(os.path.join(qdir, q))
        ae.docker_run(f"./df_fuzz.sh '{h_rel}' '{seed_rel}' {reg_hash} '{q_rel}'", timeout=600)
        done += 1
    return done


def figure5(res_dir, harnesses, args):
    bars, raw = [], {}
    for h in harnesses:
        tee = tee_of(h)
        df_dir = os.path.join(h, "df_fuzz")
        if not os.path.isdir(df_dir):
            continue
        explore_cov = set()
        cov_dir = os.path.join(h, "out", "cov")
        if os.path.isdir(cov_dir):
            for f in os.listdir(cov_dir):
                if f.endswith(".cov"):
                    explore_cov |= drcov.parse(os.path.join(cov_dir, f), tee)
        for snap in sorted(os.listdir(df_dir))[: args.max_snapshots]:
            snap_cov_dir = os.path.join(df_dir, snap, "out", "cov")
            if args.regen_faf_cov and not os.path.isdir(snap_cov_dir):
                regen_faf_cov(h, snap, args.max_queue)
            if not os.path.isdir(snap_cov_dir):
                continue
            covs = [os.path.join(snap_cov_dir, f) for f in sorted(os.listdir(snap_cov_dir))
                    if f.endswith(".cov")]
            if not covs:
                continue
            base = drcov.parse(covs[0], tee)          # deterministic prefix: up to the fetch
            union = set()
            for c in covs:
                union |= drcov.parse(c, tee)
            seed = "_".join(snap.split("_")[:-1])
            seed_cov_path = os.path.join(cov_dir, seed + ".cov")
            seed_cov = drcov.parse(seed_cov_path, tee) if os.path.exists(seed_cov_path) else set()
            only_faf = union - base - seed_cov - explore_cov
            also_seed = (union - base) & seed_cov
            also_explore = (union - base - seed_cov) & explore_cov
            bars.append((os.path.relpath(h, ae.REPO_DIR), snap,
                         len(base), len(also_seed), len(also_explore), len(only_faf)))

    if not bars:
        ae.warn("no Fetch-Anchored Fuzzing coverage found; re-run with --regen-faf-cov "
                "(needs snapshots with a queue, i.e. after E3)")
        return raw, False

    by_ta = {}
    for ta, snap, a, b, c, d in bars:
        by_ta.setdefault(ta, []).append((snap, a, b, c, d))
    n = len(by_ta)
    cols = min(4, n)
    rowsn = (n + cols - 1) // cols
    fig, axes = plt.subplots(rowsn, cols, figsize=(3.2 * cols, 2.4 * rowsn), squeeze=False)
    for idx, (ta, entries) in enumerate(sorted(by_ta.items())):
        ax = axes[idx // cols][idx % cols]
        x = range(len(entries))
        base = [e[1] for e in entries]
        seed = [e[2] for e in entries]
        expl = [e[3] for e in entries]
        faf = [e[4] for e in entries]
        ax.bar(x, base, color="tab:blue")
        ax.bar(x, seed, bottom=base, color="tab:orange")
        ax.bar(x, expl, bottom=[a + b for a, b in zip(base, seed)], color="tab:green")
        ax.bar(x, faf, bottom=[a + b + c for a, b, c in zip(base, seed, expl)], color="tab:red")
        ax.set_title(ta.split("/")[-1], fontsize=8)
        ax.tick_params(labelsize=6)
    for idx in range(n, rowsn * cols):
        axes[idx // cols][idx % cols].axis("off")
    fig.supylabel("# Basic Blocks", fontsize=9)
    fig.supxlabel("Snapshots", fontsize=9)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(res_dir, f"figure5.{ext}"), dpi=200)
    plt.close(fig)

    with open(os.path.join(res_dir, "figure5.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["harness", "snapshot", "bbs_until_second_fetch", "also_in_df_seed",
                    "also_in_exploration", "only_in_faf"])
        for row in bars:
            w.writerow(row)
    raw = {"snapshots": len(bars),
           "only_faf_total": sum(b[5] for b in bars)}
    ae.ok(f"Figure 5 written ({len(bars)} snapshots)")
    if raw["only_faf_total"] == 0:
        ae.warn("all basic blocks were already covered before Fetch-Anchored Fuzzing: the "
                "coverage shipped for the FAF queues is sparse. Run E3 first and then "
                "'./ae.sh e8_figures --regen-faf-cov' to replay the queues of the fresh "
                "snapshots, which is what the red/green parts of Figure 5 are computed from.")
    return raw, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harnesses", nargs="*", default=None,
                    help="default: every harness with campaign data")
    ap.add_argument("--regen-faf-cov", action="store_true",
                    help="replay Fetch-Anchored Fuzzing queue entries to obtain coverage")
    ap.add_argument("--max-snapshots", type=int, default=12)
    ap.add_argument("--max-queue", type=int, default=25)
    args = ap.parse_args()

    res_dir = os.path.join(ae.RESULTS_DIR, "e8_figures")
    os.makedirs(res_dir, exist_ok=True)

    harnesses = ([os.path.join(ae.REPO_DIR, h) for h in args.harnesses]
                 if args.harnesses else ae.all_harnesses())
    harnesses = [h for h in harnesses if tee_of(h) in TEES]

    f4, ok4 = figure4(res_dir, harnesses)
    f5, ok5 = figure5(res_dir, harnesses, args)

    in_range = [v for v in f4.values() if v["final_percent"]]
    checks = {"figure 4 generated": ok4, "figure 5 generated": ok5}
    for k, v in checks.items():
        ae.verdict(v, k)
    if in_range:
        lo = min(v["final_percent"] for v in in_range)
        hi = max(v["final_percent"] for v in in_range)
        ae.log(f"basic block coverage across TAs: {lo:.1f}% - {hi:.1f}% "
               f"(paper: 15-30% after 24 h of Exploration)")

    ae.write_report("e8_figures", {"figure4": f4, "figure5": f5, "checks": checks})
    ae.exit_with({"figure 4 generated": ok4})


if __name__ == "__main__":
    main()
