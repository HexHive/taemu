#!/usr/bin/env python3
"""E6 - Table IV: shared memory double fetches in TAs written in Rust
(Section VI).

The Rust TAs are OP-TEE TAs built from the Teaclave TrustZone SDK examples and
from an independent GitHub project; they are shipped in optee/tas with the
harnesses in optee/harness. Running Exploration on them shows that memory-safe
languages do not protect against shared-memory double fetches: the TA obtains a
mutable [u8] slice over normal-world memory (std::slice::from_raw_parts_mut),
which the app can keep modifying.

Claim under test: four of the six Rust TAs that operate on shared memory
contain double fetches (Table IV).

Budget:  AE_EXPLORE_TIME seconds per TA (paper: the same budget as the COTS
         campaign, 5 x 24 h).
Output:  ae/results/e6_rust/{table4.txt,csv,tex}
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))
sys.path.insert(0, HERE)

import aelib as ae
import tables
import e1_exploration as stage1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--time", type=int, default=int(ae.cfg("AE_EXPLORE_TIME", "300")))
    ap.add_argument("--skip-fuzzing", action="store_true")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    paper = tables.paper_tables()["table4"]
    res_dir = os.path.join(ae.RESULTS_DIR, "e6_rust")
    os.makedirs(res_dir, exist_ok=True)

    entries = []
    for row in paper:
        h = os.path.join(ae.REPO_DIR, row["harness"])
        if not os.path.exists(os.path.join(h, "harness.py")):
            ae.warn(f"{row['harness']}: harness missing from the artifact")
            continue
        if not ae.ta_of(h):
            ae.warn(f"{row['harness']}: TA binary missing from the artifact")
            continue
        entries.append((row, h))

    if not entries:
        ae.fail("no Rust TA harness is usable in this artifact")
        sys.exit(1)

    works = [stage1.stage(h, args.keep) for _, h in entries]
    if not args.skip_fuzzing:
        ae.log(f"exploring {len(works)} Rust TAs for {args.time}s each")
        ae.parallel(stage1.explore, [(w, args.time, 0) for w in works])
    stage1.deduplicate(works)
    stage1.annotate(works)

    rows, detail = [], {}
    with_df = 0
    for (row, h), w in zip(entries, works):
        _, fetches, snaps = stage1.count(w)
        detail[row["ta"]] = {"harness": row["harness"], "overlapped_fetches": fetches,
                            "snapshots": snaps, "paper": row["double_fetches"]}
        if fetches:
            with_df += 1
        rows.append([row["ta"], row["shm_operation"],
                     tables.cmp_cell(fetches, row["double_fetches"]), snaps])

    tables.write(res_dir, "table4",
                 ["TA", "SHM Operation", "# Detected Double Fetches", "# snapshots"],
                 rows,
                 title=f"Table IV: Rust TAs that operate on shared memory "
                       f"({args.time}s of Exploration per TA)",
                 notes=["The paper's counts come from a full-length campaign; a short AE budget "
                        "finds fewer fetches, but the TAs *with* double fetches should still be "
                        "the ones the paper reports.",
                        "The paper fuzzed only tcp_client of the udp/tcp pair, as both have an "
                        "identical operation on shared memory."],
                 caption="The Rust TAs that operate on shared memory.",
                 label="tab:rust")

    expected = {r["ta"] for r in paper if r["double_fetches"] > 0}
    found = {ta for ta, d in detail.items() if d["overlapped_fetches"] > 0}
    checks = {
        "double fetches found in Rust TAs": with_df > 0,
        "TAs with double fetches match the paper": found == (expected & set(detail)),
    }
    for k, v in checks.items():
        ae.verdict(v, k)
    if found != (expected & set(detail)):
        ae.warn(f"  expected {sorted(expected & set(detail))}, found {sorted(found)}")

    ae.write_report("e6_rust", {"budget_seconds": args.time, "tas": detail,
                                "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
