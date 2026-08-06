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
    "e1_exploration":  "Stage 1 finds overlapped fetches in TAs and turns them into snapshots",
    "e2_faf":          "Stage 2 fuzzes the second fetch of a snapshot and finds crashes",
    "e3_distillation": "Stage 3 keeps only crashes that need the shared-memory race",
    "e4_table1":       "Table I: dataset, overlapped fetches, crashes, distilled crashes",
    "e5_figures":      "Figures 4 and 5: coverage of Exploration and of Fetch-Anchored Fuzzing",
    "e6_vulns":        "Table II: the six TOCTTOU vulnerabilities reproduce in the emulator",
    "e7_rust":         "Table IV: Rust TAs are affected by shared memory double fetches",
    "e8_reshaping":    "Table V: only a small fraction of executions triggers a double fetch",
    "e9_mitigation":   "Section VII: opt-in mitigation for OP-TEE closes the double fetch",
}


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
        if name == "e4_table1":
            m = data.get("measured", {}).get("all", {})
            highlight = (f"[{data.get('source', 'campaign')}] {m.get('tas_no_local_copy')} TAs "
                         f"w/o local copy, {m.get('crashes')} crashes, "
                         f"{m.get('crashes_distilled')} distilled")
        elif name == "e1_exploration":
            highlight = (f"{data.get('tas_with_overlapped_fetches')} TAs with overlapped fetches, "
                         f"{data.get('total_snapshots')} snapshots")
        elif name == "e2_faf":
            highlight = f"{data.get('total_crashes')} crashes"
        elif name == "e3_distillation":
            highlight = f"{data.get('distilled')} shared-memory-only crashes"
        elif name == "e6_vulns":
            highlight = (f"{data.get('reproduced')}/{len(data.get('results', []))} reproduced "
                         f"[{data.get('mode', 'poc')}]")
        elif name == "e7_rust":
            tas = data.get("tas", {})
            highlight = f"{sum(1 for v in tas.values() if v['overlapped_fetches'])} of {len(tas)} Rust TAs"
        elif name == "e8_reshaping":
            highlight = (f"{data.get('percent')}% of executions (paper: 11%), "
                         f"over {data.get('harnesses_with_data', '?')} harnesses with "
                         f"recorder data")
        elif name == "e5_figures":
            highlight = ", ".join(sorted(k for k in (data.get("produced") or {})
                                         if k.endswith(".png")))
        elif name == "e9_mitigation":
            df = data.get("double_fetch", {})
            if df:
                highlight = ", ".join(
                    f"{k}: {v['differ']}/{v['total']} raced fetches differ"
                    for k, v in df.items())
            else:
                highlight = "patch + benchmark"
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
        for p in sorted(glob.glob(os.path.join(ae.RESULTS_DIR, "*", "*.txt")) +
                        glob.glob(os.path.join(ae.RESULTS_DIR, "*", "*.pdf")) +
                        glob.glob(os.path.join(ae.RESULTS_DIR, "*", "*.png")) +
                        glob.glob(os.path.join(ae.RESULTS_DIR, "*", "*.csv"))):
            f.write(f"- `{os.path.relpath(p, ae.REPO_DIR)}`\n")
    ae.ok(f"summary written to {os.path.relpath(ae.RESULTS_DIR, ae.REPO_DIR)}/summary.md")


if __name__ == "__main__":
    main()
