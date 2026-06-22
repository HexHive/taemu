#!/bin/bash
# Triage 9811_mc multi-cmd crashes: replay each, classify real-OOB vs NOTIMPL artifact.
cd /srv/emulator
echo "### 9811_mc crash files:"
ls -la ../mitee/harness/9811_mc/out/default/crashes/ 2>/dev/null | grep -vE "README|^total|^d"
for f in ../mitee/harness/9811_mc/out/default/crashes/id:*; do
  [ -f "$f" ] || continue
  echo "### CRASH $(basename "$f")"
  TAEMU_MULTI_CMD=6 REPLAY_TIMEOUT=40 timeout 40 python3 -m emulate --fuzz_replay "$f" --fuzz_harness ../mitee/harness/9811_mc/harness.py rootfs/9811c1f6-47e3-5cea-ae6ef62ba433c4fd.ta 2>&1 \
    | grep -vE "hooking inline|redzone hook" \
    | grep -iE "9811-mc|out-of-bound|UC_ERR|UNMAPPED|lr:|not implemented|Invoke|reach end|returned" | tail -20
  echo "---"
done
echo "### TRIAGE DONE"
