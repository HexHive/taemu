#!/bin/bash
# fuzz_probe.sh <harness_dir_rel> <uuid> <seconds> [CRASH_NOTIMPL]
# Runs afl-fuzz for <seconds> on the given harness/TA inside the ta_emu
# container (network-isolated, parallel-safe) and prints fuzzer_stats so we can
# tell whether the TA actually *runs* under InvokeCommand (corpus grows /
# coverage) vs. just booting. Seeds the in/ dir with sized random inputs if
# empty. Pass CRASH_NOTIMPL as 4th arg to surface unimplemented APIs reached on
# the invoke path (they become AFL crashes).
set -u
HDIR="$1"; UUID="$2"; SECS="${3:-60}"; CN="${4:-}"
REPO=/home/lamb/opt/TA_GP_emulator
name="fz_$(basename "$HDIR")_${UUID: -6}"
docker rm -f "$name" >/dev/null 2>&1

ENVCN=""
[ -n "$CN" ] && ENVCN="-e TAEMU_CRASH_NOTIMPL=1"

docker run --rm --name "$name" --network none $ENVCN \
  -e PYTHONUNBUFFERED=1 -e AFL_SKIP_CPUFREQ=1 -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  -e AFL_FORKSRV_INIT_TMOUT=99999 -e AFL_NO_FASTRESUME=1 -e AFL_AUTORESUME=1 -e AFL_NO_UI=1 \
  -e AFL_BENCH_UNTIL_CRASH=0 \
  -v "$REPO":/srv -w /srv/emulator ta_emu bash -c "
    set -e
    H=/srv/$HDIR
    cp ../teegris/tas/$UUID.ta rootfs/ && cp ../teegris/tas/$UUID.json rootfs/
    # ensure seeds exist (sized so length-gated harnesses don't reject everything)
    mkdir -p \$H/in
    if [ -z \"\$(ls -A \$H/in 2>/dev/null)\" ]; then
      python3 -c \"import os,random; random.seed(1); open('\$H/in/s0','wb').write(bytes(random.randrange(256) for _ in range(0x420)))\"
      python3 -c \"open('\$H/in/s1','wb').write(b'\\\\x00'*0x420)\"
      python3 -c \"open('\$H/in/s2','wb').write(b'\\\\x41'*0x100)\"
    fi
    rm -rf \$H/out; mkdir -p \$H/out
    timeout ${SECS} afl-fuzz -V ${SECS} -t 5000 -i \$H/in -o \$H/out -m none -U -- \
      python3 -m emulate --fuzz @@ --fuzz_harness \$H/harness.py rootfs/$UUID.ta >/tmp/aflout 2>&1 || true
    echo '===== fuzzer_stats ====='
    grep -E 'execs_done|execs_per_sec|corpus_count|saved_crashes|saved_hangs|pending_total|bitmap_cvg|cycles_done' \$H/out/default/fuzzer_stats 2>/dev/null || { echo 'NO fuzzer_stats — afl tail:'; tail -25 /tmp/aflout; }
    echo '===== crashes ====='
    ls \$H/out/default/crashes 2>/dev/null | grep -v README | head || echo '(none)'
  "
docker rm -f "$name" >/dev/null 2>&1
