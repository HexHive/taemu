#!/bin/bash
# fuzz_generic.sh <uuid> <seconds> [CRASH_NOTIMPL]
# Drives a TA's InvokeCommand under the TA-agnostic generic harness for
# <seconds>, in an isolated container, and prints fuzzer_stats. Tells whether
# the TA *runs* (corpus_count/coverage grow, execs accumulate, no crash) vs.
# only boots. Pass CRASH_NOTIMPL as a 3rd arg to make unimplemented APIs on the
# invoke path surface as AFL crashes (so we can enumerate remaining gaps).
set -u
UUID="$1"; SECS="${2:-60}"; CN="${3:-}"
REPO=/home/lamb/opt/TA_GP_emulator
name="fg_${UUID: -6}"
docker rm -f "$name" >/dev/null 2>&1
ENVCN=""; [ -n "$CN" ] && ENVCN="-e TAEMU_CRASH_NOTIMPL=1"

docker run --rm --name "$name" --network none $ENVCN \
  -e PYTHONUNBUFFERED=1 -e AFL_SKIP_CPUFREQ=1 -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  -e AFL_FORKSRV_INIT_TMOUT=99999 -e AFL_NO_FASTRESUME=1 -e AFL_AUTORESUME=1 -e AFL_NO_UI=1 \
  -v "$REPO":/srv -w /srv/emulator ta_emu bash -c "
    set -e
    W=/tmp/fg_$UUID
    rm -rf \$W; mkdir -p \$W/in \$W/out
    cp ../teegris/tas/$UUID.ta rootfs/ && cp ../teegris/tas/$UUID.json rootfs/
    python3 -c \"import random; random.seed(2); open('\$W/in/s0','wb').write(bytes(random.randrange(256) for _ in range(0x300)))\"
    python3 -c \"open('\$W/in/s1','wb').write(bytes(range(256))*3)\"
    # seeds with small / known-base command ids + all-memref ptypes (0x777),
    # so the fuzzer starts from plausibly-valid (cmd,ptypes) and explores around
    python3 -c \"import struct; [open('\$W/in/c%02d'%i,'wb').write(struct.pack('<IH',c,0x777)+bytes(0x200)) for i,c in enumerate([0,1,2,3,7,0x63,0x7e,0xd2,0x94,0xc000c10,0xc000c02])]\"
    timeout ${SECS} afl-fuzz -V ${SECS} -t 5000 -i \$W/in -o \$W/out -m none -U -- \
      python3 -m emulate --fuzz @@ --fuzz_harness /srv/teegris/harness/_generic/harness.py rootfs/$UUID.ta >/tmp/aflout 2>&1 || true
    echo '===== fuzzer_stats ====='
    grep -E 'execs_done|execs_per_sec|corpus_count|saved_crashes|saved_hangs|bitmap_cvg|cycles_done|max_depth' \$W/out/default/fuzzer_stats 2>/dev/null || { echo 'NO STATS — afl tail:'; tail -30 /tmp/aflout; }
    echo '===== crash inputs (if any) ====='
    ls \$W/out/default/crashes 2>/dev/null | grep -v README | head
    # if crashes exist, replay one to capture the cause
    C=\$(ls \$W/out/default/crashes 2>/dev/null | grep -v README | head -1)
    if [ -n \"\$C\" ]; then
      echo '===== replay of first crash (cause) ====='
      python3 -m emulate --fuzz_replay \$W/out/default/crashes/\$C --fuzz_harness /srv/teegris/harness/_generic/harness.py rootfs/$UUID.ta 2>&1 | grep -aiE 'not implemented|out-of-bound|CRASH|UcError|stack smashing|Panic|crash callback' | head -6
    fi
  "
docker rm -f "$name" >/dev/null 2>&1
