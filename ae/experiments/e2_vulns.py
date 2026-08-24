#!/usr/bin/env python3
"""E2 - Table II: the six TOCTTOU vulnerabilities (~15 minutes).

This is the central "reproduced" experiment. For every vulnerability of Table II
the artifact ships the proof-of-concept client that was also used on the phones
(Section V, Listing 2). Built with -DEMULATE it does not talk to a TEE driver
but to the emulator, which serves the GlobalPlatform client protocol on TCP
port 1337 and backs every memref with real System V shared memory
(emulator/emulate/ta_mgr.py:start_interactive). The PoC therefore

  1. opens a session to the TA,
  2. spawns a thread that keeps modifying the shared buffer, and
  3. invokes the vulnerable command,

i.e. it wins the race against the TA exactly as it does on a device. When the
double fetch is hit, the TA corrupts memory and the emulator reports the
violation (Unicorn exception or the built-in ASAN), which is what this
experiment checks. Winning the race is probabilistic, so the PoC is run
over and over until the TA crashes (--attempts N puts a cap on that).

  ./ae.sh e2_vulns                 # run the PoCs against the emulator
  ./ae.sh e2_vulns --replay        # instead replay the crashing input that
                                   # Fetch-Anchored Fuzzing found (needs the
                                   # campaign data, which is not in the repo)

Output: ae/results/e2_vulns/{table2.txt,csv,tex}
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

import aelib as ae
import tables

VULNS = os.path.join(os.path.dirname(HERE), "data", "vulns.json")


# --------------------------------------------------------------------- helpers


def _docker(args, timeout=120):
    p = subprocess.run(["docker"] + args, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def start_emulator(name, ta_rel):
    """Run the TA in the emulator's client-serving mode (emulator/run.sh)."""
    _docker(["rm", "-f", name], timeout=60)
    # No host networking and no shared IPC namespace: the emulator serves the
    # client protocol on 127.0.0.1:1337 and the PoC is executed *inside* this
    # very container, so both the socket and the System V shared memory stay
    # private to it. That is what lets the six vulnerabilities run in parallel -
    # with --network host they would all fight over port 1337.
    rc, out = _docker([
        "run", "-d", "--name", name,
        "-v", f"{ae.REPO_DIR}:/srv", "-w", "/srv/emulator",
        ae.image(), "./run.sh", os.path.join("..", ta_rel)])
    if rc != 0:
        return False, out
    # wait until the TA is created and the socket is up
    for _ in range(60):
        time.sleep(2)
        rc, logs = _docker(["logs", name], timeout=60)
        if "TA_CreateEntryPoint" in logs and "reach end" in logs:
            return True, logs
        if not container_running(name):
            return False, logs
    return False, "emulator did not reach TA_CreateEntryPoint"


def container_running(name):
    rc, out = _docker(["ps", "--format", "{{.Names}}"], timeout=60)
    return name in out.split()


def build_poc(name, poc_rel):
    """Compile the PoC for the emulator (the 'emulator' target of its Makefile)."""
    return _docker(["exec", name, "bash", "-c",
                    f"cd '/srv/{poc_rel}/jni' && gcc -g3 -O0 -DEMULATE poc.c -o /tmp/poc"],
                   timeout=300)


def run_one(entry, attempts, replay):
    if replay:
        return replay_crash(entry)

    poc_rel = entry.get("poc")
    ta_rel = entry.get("ta_path")
    logdir = os.path.join(ae.RESULTS_DIR, "e2_vulns", "logs")
    os.makedirs(logdir, exist_ok=True)

    if not poc_rel or not os.path.isdir(os.path.join(ae.REPO_DIR, poc_rel, "jni")):
        return dict(entry, status="missing", reproduced=False, distilled=None,
                    indicators=[], attempts=0,
                    detail=f"no proof-of-concept sources in {poc_rel}")

    name = f"ae_poc_{entry['id']}"[:60]
    budget = f"up to {attempts} attempts" if attempts else "until it crashes"
    ae.log(f"[{entry['id']}] {poc_rel} vs {os.path.basename(ta_rel)} ({budget})")

    poc_out, emu_log, indicators, used = [], "", [], 0
    while True:
        used += 1
        # A fresh emulator per attempt: the PoC finalizes its context at the end
        # of main(), which destroys the TA, and reusing a torn-down TA would let
        # state from a previous run leak into the next one - a crash then would
        # not be attributable to the race. Restarting also mirrors what happens
        # on a phone, where each PoC run gets a fresh TA instance.
        up, logs = start_emulator(name, ta_rel)
        if not up:
            open(os.path.join(logdir, entry["id"] + "_emulator.log"), "w").write(logs)
            _docker(["rm", "-f", name])
            return dict(entry, status="error", reproduced=False, distilled=None,
                        indicators=[], attempts=used,
                        detail="the emulator did not start for this TA")

        rc, out = build_poc(name, poc_rel)
        if rc != 0:
            open(os.path.join(logdir, entry["id"] + "_build.log"), "w").write(out)
            _docker(["rm", "-f", name])
            return dict(entry, status="error", reproduced=False, distilled=None,
                        indicators=[], attempts=used, detail="the PoC did not compile")

        rc, out = _docker(["exec", name, "timeout", "120", "/tmp/poc"], timeout=180)
        poc_out.append(f"--- attempt {used}\n{out}")
        rc, emu_log = _docker(["logs", name], timeout=120)
        _docker(["rm", "-f", name])

        indicators = ae.classify_crash(emu_log)
        if indicators:
            break
        if attempts and used >= attempts:
            break
        if used % 10 == 0:
            ae.log(f"[{entry['id']}] still racing ({used} runs)")

    open(os.path.join(logdir, entry["id"] + "_emulator.log"), "w").write(emu_log)
    open(os.path.join(logdir, entry["id"] + "_poc.log"), "w").write("\n".join(poc_out))

    asan = [l.strip() for l in emu_log.splitlines()
            if "out-of-bound" in l or "uaf on" in l]
    return dict(entry, status="ok", reproduced=bool(indicators), distilled=None,
                indicators=indicators, asan=asan[:3], attempts=used,
                detail="" if indicators else
                       f"no memory-safety violation in {used} runs")


def replay_crash(entry):
    """Alternative check: replay the crashing value Fetch-Anchored Fuzzing found."""
    src = os.path.join(ae.REPO_DIR, entry["harness"])
    crash_path = os.path.join(ae.REPO_DIR, entry["crash"])
    seed_path = os.path.join(src, "in", "suspicious_inputs_replay", entry["seed"])
    if not os.path.exists(crash_path) or not os.path.exists(seed_path):
        return dict(entry, status="missing", reproduced=False, distilled=False,
                    indicators=[], attempts=0,
                    detail="campaign data (in/, df_fuzz/) is not part of the git "
                           "repository - unpack the campaign archive, or drop "
                           "--replay to run the PoC instead")

    crash = {"snapshot": entry["snapshot"], "seed": entry["seed"],
             "seed_path": seed_path, "reg_hash": entry["reg_hash"], "crash": crash_path}
    work = os.path.join(ae.RESULTS_DIR, "e2_vulns", "work", entry["id"])
    shutil.rmtree(work, ignore_errors=True)
    ae.stage_harness(src, work, seeds=[seed_path], crashes=[crash])

    h_rel = ae.rel_to_emulator(work)
    seed_rel = ae.rel_to_emulator(os.path.join(work, "in", "suspicious_inputs_replay",
                                               entry["seed"]))
    crash_rel = ae.rel_to_emulator(os.path.join(
        work, "df_fuzz", entry["snapshot"], "out", "default", "crashes",
        os.path.basename(crash_path)))
    logdir = os.path.join(ae.RESULTS_DIR, "e2_vulns", "logs")
    os.makedirs(logdir, exist_ok=True)

    ae.log(f"[{entry['id']}] replaying the crashing double fetch ...")
    rc, out = ae.docker_run(
        f"./df_fuzz.sh '{h_rel}' '{seed_rel}' {entry['reg_hash']} '{crash_rel}'", timeout=1800)
    open(os.path.join(logdir, entry["id"] + "_replay.log"), "w").write(out)
    indicators = ae.classify_crash(out)

    ae.log(f"[{entry['id']}] running Distillation ...")
    rc, out2 = ae.docker_run(
        f"./df_validate.sh '{h_rel}' '{seed_rel}' {entry['reg_hash']} '{crash_rel}'", timeout=1800)
    open(os.path.join(logdir, entry["id"] + "_distill.log"), "w").write(out2)
    df_marker = os.path.join(work, "df_fuzz", entry["snapshot"], "out", "default",
                             "crashes", os.path.basename(crash_path) + ".df")
    distilled = ae.df_validated(out2) or os.path.exists(df_marker)

    asan = [l.strip() for l in out.splitlines() if "out-of-bound" in l or "uaf on" in l]
    return dict(entry, status="ok", reproduced=bool(indicators), distilled=bool(distilled),
                indicators=indicators, asan=asan[:3], attempts=1, detail="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", help="only these vulnerability ids")
    ap.add_argument("--attempts", type=int, default=0,
                    help="stop after this many runs of the PoC (default: 0 = keep "
                         "running it until the TA crashes)")
    ap.add_argument("--replay", action="store_true",
                    help="replay the crashing input of the campaign instead of "
                         "racing the TA with the PoC")
    args = ap.parse_args()

    if not os.path.exists(VULNS):
        ae.fail(f"missing {VULNS}")
        sys.exit(1)
    entries = json.load(open(VULNS))["vulnerabilities"]
    if args.only:
        entries = [e for e in entries if e["id"] in args.only]

    res_dir = os.path.join(ae.RESULTS_DIR, "e2_vulns")
    os.makedirs(res_dir, exist_ok=True)

    # One emulator container per vulnerability, so they can run concurrently.
    results = [r for r in ae.parallel(lambda e: run_one(e, args.attempts, args.replay),
                                      entries, workers=min(ae.jobs(), len(entries))) if r]
    order = {e["id"]: i for i, e in enumerate(entries)}
    results.sort(key=lambda r: order[r["id"]])

    how = "campaign crash replay" if args.replay else "PoC against the emulator"
    rows = []
    for r in results:
        row = [r["tee"], r["uuid"], r["ta_name"], r["vuln"], "yes" if r["reproduced"] else "NO",
               ",".join(r.get("indicators", [])) or "-",
               {True: "yes", False: "no", None: "n/a"}[r.get("on_device")]]
        row.insert(5, ("yes" if r.get("distilled") else "no") if args.replay
                      else r.get("attempts", 0))
        rows.append(row)

    headers = ["TEE", "TA UUID", "TA Name", "DF Vulnerability",
               f"Reproduced ({'replay' if args.replay else 'PoC'})",
               "Crash observed", "Reproduced on device (paper)"]
    headers.insert(5, "Needs shared memory" if args.replay else "PoC runs")

    tables.write(res_dir, "table2", headers, rows,
                 title=f"Table II [{how}]",
                 caption="The vulnerabilities in commercial TAs found with ScHMuzz.",
                 label="tab:vulns")

    reproduced = sum(1 for r in results if r["reproduced"])
    checks = {"all vulnerabilities reproduce": reproduced == len(results) and results != []}
    if args.replay:
        checks["all crashes require the shared-memory race"] = (
            sum(1 for r in results if r.get("distilled")) == len(results) and results != [])
    for k, v in checks.items():
        ae.verdict(v, k)
    for r in results:
        if not r["reproduced"]:
            ae.fail(f"  {r['id']}: {r.get('detail') or 'no crash observed'}")


    ae.write_report("e2_vulns", {"mode": "replay" if args.replay else "poc",
                                 "results": results, "reproduced": reproduced,
                                 "checks": checks})
    ae.exit_with(checks)


if __name__ == "__main__":
    main()
