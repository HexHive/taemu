#!/usr/bin/env python3
"""Stage 4 of e1_automatic_df_detection: Table I.

Table I is the summary of a whole campaign, so this stage runs after the three
stages of Section III have produced one.

--source ae (the default) computes Table I over the campaign *you* just ran,
i.e. over the ae_* working harnesses that Exploration created. --source
campaign does the same for a campaign fuzzed in the harness directories
themselves, and --source all for both. No campaign data ships with the
artifact, so on an untouched checkout only --source ae has anything to count.
Either way the numbers are printed next to the ones in the paper.

It never fuzzes anything itself: it calls the artifact's own statistics script
(../statistics.sh), which counts the on-disk state of a campaign.

    # TAs                      TA corpus of the TEE (<tee>/tas)
    # TAs w/o Local Copy       TAs that operate directly on shared memory and
                               were therefore harnessed (<tee>/harness/*)
    # TAs with Overl. Fetches  harnessed TAs for which Exploration recorded at
                               least one overlapped fetch
    # Overl. Fetches           overlapped fetches recorded by Exploration
    # Overl. Fetches merged    snapshots handed to Fetch-Anchored Fuzzing
    # Crashes                  crashing inputs found by Fetch-Anchored Fuzzing
    # Crashes Distilled        crashes that Distillation attributes to the
                               shared-memory double fetch
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

TEE_LABEL = {"teegris": "TEEGris", "qsee": "QSEE", "kinibi": "Kinibi",
             "mitee": "MiTEE", "beanpod": "Beanpod"}

COLUMNS = ["tas", "tas_no_local_copy", "tas_with_overlapped_fetches",
           "overlapped_fetches", "overlapped_fetches_merged",
           "crashes", "crashes_distilled"]

HEADERS = ["TEE", "# TAs", "# TAs w/o Local Copy", "# TAs w/ Overl. Fetches",
           "# Overl. Fetches", "# Overl. Fetches merged", "# Crashes",
           "# Crashes Distilled"]


def orphaned_snapshots(source):
    """Harnesses whose snapshot directories outlive their recordings.

    '# Overl. Fetches merged' counts df_fuzz/<seed>_<reghash>/ directories,
    '# Overl. Fetches' counts the records in in/suspicious_inputs*/. The merged
    count can therefore only be <= the raw count *if both are from the same
    point in time*. Deduplication (eval/deduplicate.py --enable-del) deletes
    redundant recordings after a campaign but leaves the snapshot directories
    in place, so on a pruned tree the two columns are inconsistent. Report
    exactly where.
    """
    out = {}
    for tee in ["teegris", "qsee", "kinibi", "mitee", "beanpod"]:
        hroot = os.path.join(ae.REPO_DIR, tee, "harness")
        if not os.path.isdir(hroot):
            continue
        for name in sorted(os.listdir(hroot)):
            if source == "campaign" and name.startswith("ae_"):
                continue
            if source == "ae" and not name.startswith("ae_"):
                continue
            h = os.path.join(hroot, name)
            df = os.path.join(h, "df_fuzz")
            if not os.path.isdir(df):
                continue
            snaps = len([d for d in os.listdir(df) if os.path.isdir(os.path.join(df, d))])
            metas = 0
            for sub in ("suspicious_inputs", "suspicious_inputs_replay"):
                d = os.path.join(h, "in", sub)
                if os.path.isdir(d):
                    metas += len([f for f in os.listdir(d) if f.endswith(".meta")])
            if snaps and not metas:
                out[f"{tee}/harness/{name}"] = {"snapshots": snaps, "recordings": 0}
    return out


def dataset_check():
    """The GlobalPlatform TA dataset, if it was written down.

    Only Table I's '# TAs' column needs this: which of the TA files in the
    corpus are the GlobalPlatform-compliant TAs of Section IV-a was decided by
    manual analysis and no property of the binaries distinguishes them. Every
    other column of Table I is derived from the repository, in particular
    '# TAs w/o Local Copy' = the TAs that have a harness.

    Returns {tee: {listed, expected, missing}}; an empty 'gp_tas' list means the
    dataset was not recorded and the corpus is counted instead.
    """
    path = os.path.join(os.path.dirname(HERE), "data", "dataset.json")
    if not os.path.exists(path):
        return {}
    spec = json.load(open(path))
    out = {}
    for tee, d in spec.items():
        if tee.startswith("_") or not isinstance(d, dict):
            continue
        listed = d.get("gp_tas") or []
        # Kinibi TAs are emulated with the Beanpod runtime, so their binaries
        # live in beanpod/tas (see "resolve_in" in the dataset).
        tas_dir = os.path.join(ae.REPO_DIR, d.get("resolve_in", tee), "tas")
        missing = [t for t in listed if not os.path.exists(os.path.join(tas_dir, t))]
        out[tee] = {
            "listed_gp_tas": len(listed),
            "expected_gp_tas": d.get("expected_gp_tas"),
            "listed_shm_tas": len(d.get("shm_tas") or []),
            "expected_shm_tas": d.get("expected_shm_tas"),
            "missing_from_artifact": missing,
        }
    return out


def harnessed_vs_dataset():
    """Cross-check '# TAs w/o Local Copy' against the dataset.

    The column is derived from the repository (a TA has a harness iff it
    operates on shared memory). The dataset records the same information from
    the manual analysis, so the two must agree.
    """
    path = os.path.join(os.path.dirname(HERE), "data", "dataset.json")
    if not os.path.exists(path):
        return {}
    spec = json.load(open(path))
    kinibi = {"0801_fuzz", "abcd_fuzz", "df1e_fuzz"}
    out = {}
    for tee, d in spec.items():
        if tee.startswith("_") or not isinstance(d, dict) or not d.get("shm_tas"):
            continue
        hroot = os.path.join(ae.REPO_DIR, "beanpod" if tee == "kinibi" else tee, "harness")
        have = set()
        if os.path.isdir(hroot):
            for name in sorted(os.listdir(hroot)):
                if name.startswith("ae_"):
                    continue
                if tee == "kinibi" and name not in kinibi:
                    continue
                import glob as _glob
                for ta in _glob.glob(os.path.join(hroot, name, "*.ta")):
                    have.add(os.path.basename(os.path.realpath(ta)))
        want = {os.path.basename(t) for t in d["shm_tas"]}
        out[tee] = {"in_dataset_not_harnessed": sorted(want - have),
                    "harnessed_not_in_dataset": sorted(have - want)}
    return out


def main():
    res_dir = ae.result_dir("4_table1")
    os.makedirs(res_dir, exist_ok=True)
    json_path = os.path.join(res_dir, "statistics.json")
    source = "ae"
    if "--source" in sys.argv:
        source = sys.argv[sys.argv.index("--source") + 1]
    if source not in ("campaign", "ae", "all"):
        ae.fail("--source must be campaign, ae or all")
        sys.exit(1)

    if "--annotate" in sys.argv:
        # Re-derive the is_second_fetch flags of every recording before
        # counting. Deterministic and idempotent, but it rewrites the .meta
        # files that Exploration produced, so it is opt-in.
        ae.log("annotating overlapped fetches")
        subprocess.run(
            [sys.executable, os.path.join(ae.REPO_DIR, "eval", "annotate_fetches.py"),
             "--path", ae.REPO_DIR, "--dirs", "both"],
            cwd=os.path.join(ae.REPO_DIR, "eval"),
            env=dict(os.environ, TAEMU_ROOT=ae.REPO_DIR))


    p = subprocess.run(
        ["bash", os.path.join(ae.REPO_DIR, "statistics.sh"), "--detail",
         "--include", source, "--json", json_path],
        cwd=ae.REPO_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=dict(os.environ, TAEMU_ROOT=ae.REPO_DIR))
    out = p.stdout.decode("utf-8", "replace")
    open(os.path.join(res_dir, "statistics.log"), "w").write(out)
    if not os.path.exists(json_path):
        ae.fail("statistics.sh produced no output")
        print(out[-2000:])
        sys.exit(1)

    measured = json.load(open(json_path))
    paper = tables.paper_tables()["table1"]

    # '# TAs' is the only column that cannot be derived from the repository. If
    # the dataset was written down in ae/data/dataset.json, use it; otherwise
    # keep the corpus count and say so below the table.
    ds = dataset_check()
    dataset_used = False
    for tee, d in ds.items():
        if d["listed_gp_tas"] and tee in measured["tees"]:
            measured["tees"][tee]["tas"] = d["listed_gp_tas"]
            dataset_used = True
    if dataset_used:
        measured["all"]["tas"] = sum(t["tas"] for t in measured["tees"].values())

    rows = []
    for tee in ["teegris", "qsee", "kinibi", "mitee", "beanpod"]:
        m = measured["tees"][tee]
        p_row = paper[TEE_LABEL[tee]]
        rows.append([TEE_LABEL[tee]] +
                    [tables.cmp_cell(m[c], p_row[i]) for i, c in enumerate(COLUMNS)])
    rows.append(None)
    m = measured["all"]
    p_row = paper["all"]
    rows.append(["all"] + [tables.cmp_cell(m[c], p_row[i]) for i, c in enumerate(COLUMNS)])

    # When this runs as a stage of e1_automatic_df_detection the merged
    # experiment prints Table I once, at the end, as its deliverable.
    tables.write(res_dir, f"table1_{source}", HEADERS, rows, quiet=bool(ae.STAGE_OF),
                 title=f"Table I [{source}]",
                 caption="Overview of the results of our large-scale study of shared memory "
                         "usage and vulnerabilities in TAs.",
                 label="tab:overview")

    deltas = {}
    for tee in ["teegris", "qsee", "kinibi", "mitee", "beanpod"]:
        m = measured["tees"][tee]
        p_row = paper[TEE_LABEL[tee]]
        d = {c: [m[c], p_row[i]] for i, c in enumerate(COLUMNS) if m[c] != p_row[i]}
        if d:
            deltas[TEE_LABEL[tee]] = d

    consistent = (measured["all"]["overlapped_fetches_merged"]
                  <= measured["all"]["overlapped_fetches"])
    checks = {
        "statistics computed": True,
        "all five TEEs present": all(measured["tees"][t]["tas"] > 0 for t in measured["tees"]),
        "crashes distilled > 0": measured["all"]["crashes_distilled"] > 0,
    }
    if source == "ae":
        # For a campaign produced in this evaluation the invariant must hold:
        # merging contiguous second fetches cannot create fetches.
        checks["snapshots <= recorded overlapped fetches"] = consistent
    elif not consistent:
        ae.warn("snapshots > recorded overlapped fetches (pruned campaign data)")
    for k, v in checks.items():
        ae.verdict(v, k)
    if deltas and source != "ae":
        for tee, d in deltas.items():
            for col, (mv, pv) in d.items():
                ae.warn(f"{tee:8s} {col:32s} {mv} != {pv} (paper)")

    orphans = orphaned_snapshots(source)
    for k, v in sorted(orphans.items(), key=lambda kv: -kv[1]["snapshots"]):
        ae.warn(f"{k}: {v['snapshots']} snapshots, 0 recordings")

    xcheck = harnessed_vs_dataset()
    for tee, d in sorted(xcheck.items()):
        for t in d["in_dataset_not_harnessed"]:
            ae.warn(f"{tee}: {t} shm=yes but no harness")
        for t in d["harnessed_not_in_dataset"]:
            ae.warn(f"{tee}: {t} harnessed but shm=no")
    if xcheck and not any(v["in_dataset_not_harnessed"] or v["harnessed_not_in_dataset"]
                          for v in xcheck.values()):
        ae.ok("harnesses match the shm TAs of the dataset")

    for tee, d in ds.items():
        if d["missing_from_artifact"]:
            ae.warn(f"{tee}: {len(d['missing_from_artifact'])} dataset TAs missing")
        elif d["listed_gp_tas"]:
            ae.ok(f"{tee}: {d['listed_gp_tas']}/{d['listed_gp_tas']} dataset TAs present")

    ae.write_report("4_table1", {"source": source, "measured": measured, "paper": paper,
                                  "deltas": deltas, "checks": checks,
                                  "dataset": ds, "dataset_vs_harnesses": xcheck,
                                  "orphaned_snapshots": orphans})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
