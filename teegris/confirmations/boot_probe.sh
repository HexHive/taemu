#!/bin/bash
# boot_probe.sh <ta_path_rel>
# TEE-agnostic: copies the TA + its .json into rootfs, runs ONE generic-harness
# input through fuzz_replay (Create -> OpenSession -> InvokeCommand) and reports
# how far it got + the first unimplemented API, if any. The emulator auto-detects
# the TEE from magic bytes, so this works for beanpod/mitee/t6/qsee/trustedcore.
set -u
TA="$1"                       # e.g. beanpod/tas/0811....ta
REPO=/home/lamb/opt/TA_GP_emulator
base=$(basename "$TA" .ta)
name="bp_$(echo "$base" | tr -c 'a-zA-Z0-9' _ | tail -c 16)"
docker rm -f "$name" >/dev/null 2>&1
docker run --rm --name "$name" --network none -e PYTHONUNBUFFERED=1 \
  -v "$REPO":/srv -w /srv/emulator ta_emu bash -c "
    cp /srv/$TA rootfs/ 2>/dev/null; cp /srv/${TA%.ta}.json rootfs/ 2>/dev/null
    python3 -c \"import random;random.seed(2);open('/tmp/s0','wb').write(bytes(random.randrange(256) for _ in range(0x200)))\"
    timeout 40 python3 -m emulate --fuzz_replay /tmp/s0 --fuzz_harness /srv/teegris/harness/_generic/harness.py rootfs/$base.ta 2>&1 \
      | grep -aiE 'CreateEntryPoint] reach end|OpenSessionEntryPoint] reach end|InvokeCommandEntryPoint] (start|reach end)|not implemented|TEE not set|could not derive|out-of-bound|emulator stopped|Error occurred' \
      | grep -avE 'relocation at|hooking api' | head -10
  " 2>/dev/null
docker rm -f "$name" >/dev/null 2>&1
