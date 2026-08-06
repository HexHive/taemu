#!/usr/bin/env python3
"""Collect the results of all experiments into one summary.

Reads ae/results/*/result.json and writes ae/results/summary.{txt,md}.
"""

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

CLAIMS = {
    "e0_selftest":     "artifact is functional (emulator, recording, snapshot replay, distillation)",
    "e1_automatic_df_detection":
                       "Section III: the pipeline finds overlapped fetches, turns them into "
                       "crashes and keeps the ones that need the race - Table I, Figures 4 and 5",
    "e2_vulns":        "Table II: the six TOCTTOU vulnerabilities reproduce in the emulator",
    "e3_rust":         "Table IV: Rust TAs are affected by shared memory double fetches",
    "e4_reshaping":    "Table V: only a small fraction of executions triggers a double fetch",
}

# The pipeline's stages report separately, below its result directory.
PIPELINE_STAGES = ["1_exploration", "2_faf", "3_distillation", "4_table1", "5_figures"]


def stage(name, sub):
    p = os.path.join(ae.RESULTS_DIR, name, sub, "result.json")
    try:
        return json.load(open(p))
    except Exception:
        return {}


def pipeline_highlight(name):
    """One line for the whole campaign, from the stages that produced it."""
    bits = []
    e = stage(name, "1_exploration")
    if e:
        bits.append(f"{e.get('tas_with_overlapped_fetches')} TAs with overlapped fetches, "
                    f"{e.get('total_snapshots')} snapshots")
    f = stage(name, "2_faf")
    if f:
        bits.append(f"{f.get('total_crashes')} crashes")
    d = stage(name, "3_distillation")
    if d:
        bits.append(f"{d.get('distilled')} need the race")
    t = stage(name, "4_table1")
    if t:
        m = t.get("measured", {}).get("all", {})
        bits.append(f"Table I: {m.get('tas_no_local_copy')} TAs w/o local copy")
    g = stage(name, "5_figures")
    if g:
        pngs = sorted(k for k in (g.get("produced") or {}) if k.endswith(".png"))
        if pngs:
            bits.append(", ".join(pngs))
    return "; ".join(bits)


def main():
    rows = []
    payloads = {}
    for name in CLAIMS:
        p = os.path.join(ae.RESULTS_DIR, name, "result.json")
        if not os.path.exists(p):
            rows.append([name, CLAIMS[name], "not run", ""])
            continue
        data = json.load(open(p))
        payloads[name] = data
        checks = data.get("checks", {})
        passed = sum(1 for v in checks.values() if v)
        status = "ok" if passed == len(checks) and checks else (
            "partial" if passed else "FAILED")
        highlight = ""
        if name == "e1_automatic_df_detection":
            highlight = pipeline_highlight(name)
        elif name == "e2_vulns":
            highlight = (f"{data.get('reproduced')}/{len(data.get('results', []))} reproduced "
                         f"[{data.get('mode', 'poc')}]")
        elif name == "e3_rust":
            tas = data.get("tas", {})
            highlight = f"{sum(1 for v in tas.values() if v['overlapped_fetches'])} of {len(tas)} Rust TAs"
        elif name == "e4_reshaping":
            highlight = (f"{data.get('percent')}% of executions (paper: 11%), "
                         f"over {data.get('harnesses_with_data', '?')} harnesses with "
                         f"recorder data")
        rows.append([name, CLAIMS[name], status, highlight])

    txt = tables.write(ae.RESULTS_DIR, "summary",
                       ["experiment", "claim", "status", "result"], rows,
                       title="Oversharing - artifact evaluation summary")

    with open(os.path.join(ae.RESULTS_DIR, "summary.md"), "w") as f:
        f.write("# Oversharing - artifact evaluation summary\n\n")
        f.write("| experiment | claim | status | result |\n|---|---|---|---|\n")
        for r in rows:
            f.write("| " + " | ".join(str(c) for c in r) + " |\n")
        f.write("\nGenerated tables and figures:\n\n")
        arts = []
        for depth in ("*", "*/*"):
            for ext in ("txt", "pdf", "png", "csv"):
                arts += glob.glob(os.path.join(ae.RESULTS_DIR, depth, f"*.{ext}"))
        for p in sorted(set(arts)):
            f.write(f"- `{os.path.relpath(p, ae.REPO_DIR)}`\n")
    ae.ok(f"summary written to {os.path.relpath(ae.RESULTS_DIR, ae.REPO_DIR)}/summary.md")


if __name__ == "__main__":
    main()
