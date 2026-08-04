#!/usr/bin/env python3
"""Parse results_v2.csv (size + workload sweeps) -> tables + plots."""
import csv
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BENCH_OUT = os.environ.get(
    "BENCH_OUT",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "out"))
CSV = os.environ.get("RESULTS_CSV", f"{BENCH_OUT}/results_v2.csv")
PLOT = os.environ.get("PLOT_OUT", f"{BENCH_OUT}/shm_mitigation_overhead.png")

LABELS = ["baseline", "mitig_shared", "mitig_copied"]
PRETTY = {
    "baseline": "Baseline (no mitigation)",
    "mitig_shared": "Mitigation, opted-in (shared)",
    "mitig_copied": "Mitigation, not opted-in (copy)",
}
COLORS = {"baseline": "#4C78A8", "mitig_shared": "#54A24B", "mitig_copied": "#E45756"}

# rows[(sweep,label,size,work)] = median_ns
rows = {}
with open(CSV) as f:
    r = csv.reader(f)
    next(r)
    for row in r:
        if len(row) < 12 or row[2] != "RESULT":
            continue
        sweep, label = row[0], row[1]
        size, work = int(row[5]), int(row[7])
        median = int(row[11])
        rows[(sweep, label, size, work)] = median


def us(ns):
    return ns / 1000.0


# ---------- SIZE SWEEP ----------
sizes = sorted({k[2] for k in rows if k[0] == "size"})
print("\n=== SIZE sweep: median latency per invoke (µs), work=0 ===")
hdr = f"{'size(B)':>9} | " + " | ".join(f"{PRETTY[l]:>32}" for l in LABELS)
print(hdr); print("-" * len(hdr))
for s in sizes:
    base = rows[("size", "baseline", s, 0)]
    cells = []
    for l in LABELS:
        v = rows[("size", l, s, 0)]
        cells.append(f"{us(v):.2f}" if l == "baseline"
                     else f"{us(v):.2f} (+{(v-base)/base*100:.0f}%)")
    print(f"{s:>9} | " + " | ".join(f"{c:>32}" for c in cells))

# ---------- WORKLOAD SWEEP ----------
works = sorted({k[3] for k in rows if k[0] == "work"})
WS = 4096
print("\n=== WORKLOAD sweep: median latency per invoke (µs), size=4096 ===")
print(f"{'work':>9} | {'baseline':>12} | {'copy path':>12} | "
      f"{'abs delta(us)':>13} | {'overhead':>9}")
print("-" * 66)
wl_rows = []
for w in works:
    base = rows[("work", "baseline", WS, w)]
    cop = rows[("work", "mitig_copied", WS, w)]
    d = us(cop - base)
    ov = (cop - base) / base * 100.0
    print(f"{w:>9} | {us(base):>12.1f} | {us(cop):>12.1f} | "
          f"{d:>13.1f} | {ov:>8.1f}%")
    wl_rows.append((w, base, cop, rows[("work", "mitig_shared", WS, w)]))

# ---------- PLOTS ----------
fig, axes = plt.subplots(1, 3, figsize=(18, 5))

# (1) size sweep absolute
ax = axes[0]
for l in LABELS:
    ys = [us(rows[("size", l, s, 0)]) for s in sizes]
    ax.plot(sizes, ys, marker="o", label=PRETTY[l], color=COLORS[l])
ax.set_xscale("log", base=2)
ax.set_xlabel("memref buffer size (bytes)")
ax.set_ylabel("median latency per invoke (µs)")
ax.set_title("Size sweep (empty TA): latency vs buffer size")
ax.grid(True, which="both", alpha=0.3); ax.legend()

# (2) workload sweep absolute, x = baseline latency (TA work proxy)
ax = axes[1]
base_x = [us(b) for (_, b, _, _) in wl_rows]
ax.plot(base_x, base_x, marker="o", label=PRETTY["baseline"], color=COLORS["baseline"])
ax.plot(base_x, [us(sh) for (_, _, _, sh) in wl_rows], marker="o",
        label=PRETTY["mitig_shared"], color=COLORS["mitig_shared"])
ax.plot(base_x, [us(c) for (_, _, c, _) in wl_rows], marker="o",
        label=PRETTY["mitig_copied"], color=COLORS["mitig_copied"])
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("baseline invoke latency (µs)  ~ TA work per call")
ax.set_ylabel("median latency per invoke (µs)")
ax.set_title("Workload sweep (size=4KiB): copy cost is a constant add-on")
ax.grid(True, which="both", alpha=0.3); ax.legend()

# (3) workload sweep overhead %
ax = axes[2]
ov_copy = [(c - b) / b * 100 for (_, b, c, _) in wl_rows]
ov_shared = [(sh - b) / b * 100 for (_, b, _, sh) in wl_rows]
ax.plot(base_x, ov_copy, marker="o", label=PRETTY["mitig_copied"], color=COLORS["mitig_copied"])
ax.plot(base_x, ov_shared, marker="o", label=PRETTY["mitig_shared"], color=COLORS["mitig_shared"])
ax.axhline(0, color=COLORS["baseline"], lw=1, ls="--")
ax.set_xscale("log")
ax.set_xlabel("baseline invoke latency (µs)  ~ TA work per call")
ax.set_ylabel("overhead vs baseline (%)")
ax.set_title("Workload sweep: % overhead shrinks as TA work grows")
ax.grid(True, which="both", alpha=0.3); ax.legend()

fig.tight_layout()
fig.savefig(PLOT, dpi=120)
print(f"\nSaved plot: {PLOT}")
