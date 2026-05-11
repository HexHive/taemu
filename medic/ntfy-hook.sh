#!/bin/bash

set -euo pipefail

harness_path="${1:-}"
fuzz_out="${2:-}"

if [ -z "${NTFY_TOKEN:-}" ] || [ -z "${NTFY_TOPIC:-}" ]; then
    echo "ntfy hook skipped: NTFY_TOKEN and NTFY_TOPIC must be set"
    exit 0
fi

ntfy_url="${NTFY_URL:-https://ntfy.sh}"
harness_name="$(basename "$harness_path")"
crash_dir="$fuzz_out/default/crashes"
crash_count=0
latest_crash="<unknown>"

if [ -d "$crash_dir" ]; then
    crash_count="$(find "$crash_dir" -maxdepth 1 -type f ! -name 'README.txt' | wc -l)"
    latest_crash="$(find "$crash_dir" -maxdepth 1 -type f ! -name 'README.txt' -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d' ' -f2-)"
    latest_crash="${latest_crash:-<unknown>}"
fi

title="new AFL crash: $harness_name"
message="harness=$harness_path
out=$fuzz_out
crashes=$crash_count
latest=$latest_crash
host=$(hostname)"

curl -fsS \
    -H "Authorization: Bearer $NTFY_TOKEN" \
    -H "Title: $title" \
    -H "Tags: test_tube" \
    -d "$message" \
    "$ntfy_url/$NTFY_TOPIC"
