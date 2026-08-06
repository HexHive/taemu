#!/usr/bin/env python3
"""Helper: replay every replayable crash of the candidate TAs and report the
observed crash type. Used to build ae/data/vulns.json."""
import json, os, sys, shutil
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))
import aelib as ae

CANDIDATES = sys.argv[1:] or [
    "mitee/harness/377e_double_fetch_stackov",
    "mitee/harness/88ce_fuzz",
    "mitee/harness/3d08_fuzz",
    "qsee/harness/3d08_fuzz",
    "beanpod/harness/0801_fuzz",
    "teegris/harness/4662436b6d52_fuzz",
    "mitee/harness/8aaa_fuzz",
]
MAX = int(os.environ.get("PROBE_MAX", "6"))

def run(job):
    h, work, c = job
    seed_rel = ae.rel_to_emulator(os.path.join(work, "in", "suspicious_inputs_replay", c["seed"]))
    crash_rel = ae.rel_to_emulator(os.path.join(work, "df_fuzz", c["snapshot"], "out",
                                                "default", "crashes", os.path.basename(c["crash"])))
    h_rel = ae.rel_to_emulator(work)
    rc, out = ae.docker_run(f"./df_fuzz.sh '{h_rel}' '{seed_rel}' {c['reg_hash']} '{crash_rel}'", timeout=900)
    ind = ae.classify_crash(out)
    rc2, out2 = ae.docker_run(f"./df_validate.sh '{h_rel}' '{seed_rel}' {c['reg_hash']} '{crash_rel}'", timeout=900)
    val = ae.df_validated(out2)
    asan = [l.strip() for l in out.splitlines() if "out-of-bound" in l or "uaf on" in l][:2]
    return {"harness": h, "snapshot": c["snapshot"], "crash": os.path.basename(c["crash"]),
            "shipped_distilled": c["distilled"], "indicators": ind, "asan": asan,
            "distilled_now": bool(val)}

jobs = []
for h in CANDIDATES:
    src = os.path.join(ae.REPO_DIR, h)
    crashes = [c for c in ae.harness_crashes(src) if c["replayable"]]
    crashes.sort(key=lambda c: (not c["distilled"],))
    chosen = crashes[:MAX]
    if not chosen:
        ae.log(f"{h}: no replayable crash"); continue
    work = os.path.join(ae.RESULTS_DIR, "_probe_vulns", h.replace("/", "__"))
    shutil.rmtree(work, ignore_errors=True)
    ae.stage_harness(src, work, seeds={c["seed_path"] for c in chosen}, crashes=chosen)
    jobs += [(h, work, c) for c in chosen]

ae.log(f"probing {len(jobs)} crashes")
res = [r for r in ae.parallel(run, jobs) if r]
out = os.path.join(ae.RESULTS_DIR, "_probe_vulns", "probe.json")
json.dump(res, open(out, "w"), indent=2)
for r in res:
    print(f"{r['harness']:42s} {r['crash'][:28]:30s} shipped_df={r['shipped_distilled']!s:5s} "
          f"now_df={r['distilled_now']!s:5s} {r['indicators']} {r['asan']}")
