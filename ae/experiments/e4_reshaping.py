#!/usr/bin/env python3
"""E4 - Table V: how often a fuzzing iteration actually triggers a double fetch
(Section VIII-c).

Reshaping-based fuzzers (Morphuzz, EnclaveFuzz) inject data on every read of
attacker-controlled memory and therefore have to re-execute the target until
the double fetch happens again. ScHMuzz instead restores a snapshot taken right
before the second fetch. Table V quantifies the difference: across all
harnesses, only 11% of the Exploration iterations execute a code path that
contains a double fetch.

The numbers come from the campaign state:
  # Execs      execs_done of the Exploration AFL runs (out/*/fuzzer_stats)
  # Execs DF   executions that produced a shared-memory access trace which
               the recorder flagged, summed from the recorder's own bookkeeping
               (<harness>/record_meta/*hash2count.json)

This is what eval/reshaping_cmp.py --print-numbers computes; this experiment
drives it and renders the table.

Output: ae/results/e4_reshaping/{table5.txt,csv,tex}
"""

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables


def execs_of(afl_dir):
    stats = os.path.join(afl_dir, "fuzzer_stats")
    if not os.path.exists(stats):
        return 0
    for line in open(stats):
        if line.startswith("execs_done"):
            return int(line.split(":")[-1])
    return 0


def harness_numbers(harness):
    """(executions, executions that hit a double fetch, has recorder data).

    '# Execs DF' can only be computed for a harness whose recorder bookkeeping
    (record_meta/*hash2count.json) is present. Mixing harnesses that have it
    with harnesses that do not would put their executions into the denominator
    and drive the ratio to zero, so the caller drops the latter.
    """
    execs = 0
    out = os.path.join(harness, "out")
    if os.path.isdir(out):
        for sub in os.listdir(out):
            execs += execs_of(os.path.join(out, sub))
    df_execs = 0
    meta = os.path.join(harness, "record_meta")
    if os.path.isdir(meta):
        for f in os.listdir(meta):
            if f.endswith("hash2count.json"):
                try:
                    for _, v in json.load(open(os.path.join(meta, f))).items():
                        df_execs += v
                except Exception:
                    pass
    return execs, df_execs, os.path.isdir(meta)


# The paper's Table V is keyed by TA name; this evaluation's rows are keyed by
# harness. ae/data/vulns.json pins the TA name of six harnesses, which is the
# only mapping the artifact actually establishes - the rest of the paper's TAs
# cannot be tied to a harness from anything in this repository, so their rows
# say "n/a" rather than guessing.
NAME_ALIASES = {"FbSkmR": "FbCkmR"}


def paper_rows_by_harness():
    """<tee>/<uuid prefix> -> (execs, execs_df, percent) from the paper."""
    paper5 = tables.paper_tables()["table5"]
    out = {}
    for v in json.load(open(os.path.join(
            os.path.dirname(HERE), "data", "vulns.json")))["vulnerabilities"]:
        name = NAME_ALIASES.get(v["ta_name"], v["ta_name"])
        if name not in paper5:
            continue
        tee, _, harness = v["harness"].split("/")
        out[f"{tee}/{harness.split('_')[0]}"] = paper5[name]
    return out


def paper_key(rel_harness):
    """Key of a harness path, ignoring the ae_e<n>_ prefix of a working copy."""
    tee, _, harness = rel_harness.split("/")
    harness = re.sub(r"^ae_e[0-9]+_", "", harness)
    return f"{tee}/{harness.split('_')[0]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harnesses", nargs="*", default=None,
                    help="default: every harness of the artifact")
    args = ap.parse_args()

    res_dir = os.path.join(ae.RESULTS_DIR, "e4_reshaping")
    os.makedirs(res_dir, exist_ok=True)

    # The original script prints the same numbers; keep its output for reference.
    log = os.path.join(res_dir, "reshaping_cmp.log")
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(ae.REPO_DIR, "eval", "reshaping_cmp.py"),
             "--path", ae.REPO_DIR, "--print-numbers"],
            cwd=os.path.join(ae.REPO_DIR, "eval"), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=1800,
            env=dict(os.environ, TAEMU_ROOT=ae.REPO_DIR))
        open(log, "wb").write(p.stdout or b"")
    except Exception as e:
        ae.warn(f"eval/reshaping_cmp.py failed: {e}")

    harnesses = ([os.path.join(ae.REPO_DIR, h) for h in args.harnesses]
                 if args.harnesses else ae.all_harnesses())

    by_harness = paper_rows_by_harness()
    paper5 = tables.paper_tables()["table5"]
    p_execs = sum(v[0] for k, v in paper5.items() if k != "_columns")
    p_df = sum(v[1] for k, v in paper5.items() if k != "_columns")

    rows, detail = [], {}
    t_execs = t_df = 0
    skipped = []
    for h in harnesses:
        execs, df_execs, has_meta = harness_numbers(h)
        if execs == 0 and df_execs == 0:
            continue
        if not has_meta:
            skipped.append(os.path.relpath(h, ae.REPO_DIR))
            continue
        name = os.path.relpath(h, ae.REPO_DIR)
        pct = (100.0 * df_execs / execs) if execs else 0.0
        detail[name] = {"execs": execs, "execs_df": df_execs, "percent": round(pct, 1)}
        p = by_harness.get(paper_key(name))
        detail[name]["paper"] = p
        rows.append([name,
                     tables.cmp_cell(f"{execs:,}", f"{p[0]:,}" if p else "n/a"),
                     tables.cmp_cell(f"{df_execs:,}", f"{p[1]:,}" if p else "n/a"),
                     tables.cmp_cell(f"{pct:.1f}%", f"{p[2]}%" if p else "n/a")])
        t_execs += execs
        t_df += df_execs
    rows.sort(key=lambda r: float(r[3].split("%")[0]), reverse=True)
    rows.append(None)
    total_pct = (100.0 * t_df / t_execs) if t_execs else 0.0
    rows.append(["all",
                 tables.cmp_cell(f"{t_execs:,}", f"{p_execs:,}"),
                 tables.cmp_cell(f"{t_df:,}", f"{p_df:,}"),
                 tables.cmp_cell(f"{total_pct:.1f}%", f"{100.0 * p_df / p_execs:.1f}%")])

    tables.write(res_dir, "table5",
                 ["TA (harness)", "# Execs", "# Execs DF", "Execs DF %"], rows,
                 title="Table V",
                 caption="Overall executions and executions triggering overlapped fetches.",
                 label="tab:reshaping")

    checks = {
        "execution counts available": t_execs > 0,
        "double-fetch executions are a minority": 0 < total_pct < 100,
    }
    for k, v in checks.items():
        ae.verdict(v, k)
    with_df = sum(1 for v in detail.values() if v["execs_df"])
    if skipped:
        ae.warn(f"{len(skipped)} harnesses without record_meta/, excluded")

    ae.write_report("e4_reshaping", {"per_harness": detail, "execs": t_execs,
                                     "execs_df": t_df, "percent": round(total_pct, 1),
                                     "paper_percent": 11,
                                     "harnesses_with_data": len(detail),
                                     "harnesses_skipped": skipped,
                                     "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
