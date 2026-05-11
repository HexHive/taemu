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

log_dir="${SCRIPT_DIR}/logs/$(basename "$harness_path")"
mkdir -p "$log_dir"

replay_log="${log_dir}/$(basename "$last_crash" | sed 's/\.[^.]*$//').log"

set +e
"$SCRIPT_DIR/../emulator/fuzz.sh" "$harness_path" "$last_crash" >"$replay_log" 2>&1
replay_status=$?
set -e

missing_function=$(grep -Eo '^\[x\][[:space:]]+.+ called, not implemented! lr: 0x[0-9a-fA-F]+$' "$replay_log")
if [ -n "$missing_function" ]; then
    printf 'function-missing\t%s\t%s\n' "$last_crash" "$replay_status" >>"$log_dir/function-missing.txt"
else
    printf 'real-crash\t%s\t%s\n' "$last_crash" "$replay_status" >>"$log_dir/real-crashes.txt"
fi
