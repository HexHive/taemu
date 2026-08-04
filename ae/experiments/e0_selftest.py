#!/usr/bin/env python3
"""Kick-the-tires self test (~5 minutes).

Checks that the artifact is functional end to end:
  1. the controller can start emulator containers,
  2. the emulator loads a proprietary TA and executes its command handler,
  3. Exploration records shared-memory accesses (needs redis),
  4. a snapshot from the paper's campaign can be restored and the crashing
     input from Fetch-Anchored Fuzzing reproduces the vulnerability,
  5. Distillation confirms the crash needs the shared-memory race.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib"))

import aelib as ae

# The double fetch of Listing 3 / Table II: SoterApp (MiTEE) stack overflow.
HARNESS = "mitee/harness/377e_double_fetch_stackov"
SEED = "run:id:d3b07384d113edec49eaa6238ad5ff00"
REG_HASH = "205374383998289612021010690897642464208"


def main():
    results = {}
    ae.banner("E0: self test")

    # -------------------------------------------------------------- container
    rc, out = ae.docker_run("python3 -c 'import qiling, unicornafl; print(\"emulator ok\")'", timeout=300)
    results["emulator container"] = ae.verdict(
        rc == 0 and "emulator ok" in out, "emulator image runs qiling + unicornafl")

    rc, out = ae.docker_run("afl-fuzz -h 2>&1 | head -2", timeout=120)
    results["afl++"] = ae.verdict("afl-fuzz" in out.lower(), "AFL++ is available in the emulator image")

    # ------------------------------------------------------------------ redis
    rc, out = ae.docker_run(
        "python3 -c \"import redis,os;"
        "redis.Redis(host=os.environ['REDIS_HOST'],port=int(os.environ['REDIS_PORT'])).ping();"
        "print('redis ok')\"", timeout=120)
    results["redis"] = ae.verdict("redis ok" in out, "redis reachable (needed by the recorder)")

    # -------------------------------------------------- emulate + replay seed
    harness = os.path.join(ae.REPO_DIR, HARNESS)
    if not os.path.exists(os.path.join(harness, "harness.py")):
        ae.fail(f"missing harness {HARNESS}")
        ae.exit_with({"harness": False})

    seed = os.path.join(harness, "in", "suspicious_inputs_replay", SEED)
    work = os.path.join(ae.RESULTS_DIR, "e0_selftest", "work")
    crashes = [c for c in ae.harness_crashes(harness)
               if c["reg_hash"] == REG_HASH and c["distilled"]]
    if not crashes:
        crashes = [c for c in ae.harness_crashes(harness) if c["reg_hash"] == REG_HASH]
    if not crashes:
        ae.fail("no crashing input shipped for the self-test snapshot")
        ae.exit_with({"campaign data": False})
    crash = crashes[0]

    ae.log("staging a scratch copy of the harness (the campaign data is never modified)")
    ae.stage_harness(harness, work, seeds=[seed], crashes=[crash])

    h_rel = ae.rel_to_emulator(work)
    seed_rel = ae.rel_to_emulator(os.path.join(work, "in", "suspicious_inputs_replay", SEED))
    crash_rel = ae.rel_to_emulator(os.path.join(
        work, "df_fuzz", crash["snapshot"], "out", "default", "crashes",
        os.path.basename(crash["crash"])))

    ae.log("replaying the Exploration seed (Stage 1 record of the double fetch) ...")
    rc, out = ae.docker_run(f"./fuzz.sh '{h_rel}' '{seed_rel}'", timeout=900)
    open(os.path.join(ae.RESULTS_DIR, "e0_selftest", "replay.log"), "w").write(out)
    results["exploration replay"] = ae.verdict(
        "InvokeCommand returned" in out or "reach end" in out,
        "emulator executed TA_InvokeCommandEntryPoint of the TA")

    ae.log("restoring the snapshot and replaying the crashing double-fetch value ...")
    rc, out = ae.docker_run(
        f"./df_fuzz.sh '{h_rel}' '{seed_rel}' {REG_HASH} '{crash_rel}'", timeout=1200)
    open(os.path.join(ae.RESULTS_DIR, "e0_selftest", "df_replay.log"), "w").write(out)
    indicators = ae.classify_crash(out)
    results["crash reproduced"] = ae.verdict(
        bool(indicators), f"crash reproduced from the snapshot: {indicators or 'none'}")

    ae.log("running Distillation on the crash ...")
    rc, out = ae.docker_run(
        f"./df_validate.sh '{h_rel}' '{seed_rel}' {REG_HASH} '{crash_rel}'", timeout=1200)
    open(os.path.join(ae.RESULTS_DIR, "e0_selftest", "distill.log"), "w").write(out)
    df_file = os.path.join(work, "df_fuzz", crash["snapshot"], "out", "default", "crashes",
                           os.path.basename(crash["crash"]) + ".df")
    results["distillation"] = ae.verdict(
        ae.df_validated(out) or os.path.exists(df_file),
        "Distillation confirms the crash requires the shared-memory double fetch")

    ae.write_report("e0_selftest", {
        "checks": results,
        "crash_indicators": indicators,
        "harness": HARNESS,
        "snapshot": crash["snapshot"],
    })
    ae.exit_with(results)


if __name__ == "__main__":
    main()
