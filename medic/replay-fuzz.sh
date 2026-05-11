#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

harness_path="${1:-}"
fuzz_out="${2:-}"

if [ -z "$harness_path" ] || [ -z "$fuzz_out" ]; then
    echo "usage: $0 <harness_path> <fuzz_out>"
    exit 1
fi

crash_dir="$fuzz_out/default/crashes"
if [ ! -d "$crash_dir" ]; then
    echo "no-crash-dir"
    exit 1
fi

last_crash="$(find "$crash_dir" -maxdepth 1 -type f ! -name 'README.txt' -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d' ' -f2-)"
if [ -z "$last_crash" ]; then
    echo "no-crash"
    exit 1
fi

replay_log="$(mktemp)"
trap 'rm -f "$replay_log"' EXIT

set +e
"$SCRIPT_DIR/../emulator/fuzz.sh" "$harness_path" "$last_crash" >"$replay_log" 2>&1
replay_status=$?
set -e

if rg -q '^\[x\][[:space:]]+.+ called, not implemented! lr: 0x[0-9a-fA-F]+$' "$replay_log"; then
    printf 'function-missing\t%s\t%s\n' "$last_crash" "$replay_status"
else
    printf 'real-crash\t%s\t%s\n' "$last_crash" "$replay_status"
fi
