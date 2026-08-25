#!/bin/bash
# emu_poc.sh <jni_dir_rel> <poc_src> [timeout_secs]
# Compiles <poc_src> (inside <jni_dir_rel>, relative to repo root) with -DEMULATE
# inside the running emu container, then executes it. Prints PoC stdout.
# The emulator's own log is the teed file from emu_start.sh; read that separately.
set -u
JNI="$1"          # e.g. teegris/pocs/hdcp_bufov/jni
SRC="$2"          # e.g. poc.c
TMO="${3:-60}"
docker exec emu bash -c "cd /srv/${JNI} && gcc -g3 -O0 -DEMULATE ${SRC} -o /poc 2>&1 | grep -i error" && true
echo "=== PoC run ==="
timeout "${TMO}" docker exec emu /poc 2>&1
echo "=== PoC exit: $? ==="
