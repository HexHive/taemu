#!/bin/bash

set -euo pipefail

usage() {
    echo "usage: $0 <function-missing|new-crash|real-crash|afl-stopped> <harness_path> <fuzz_out> [detail]"
}

message_type="${1:-}"
if [ -z "$message_type" ]; then
    usage
    exit 1
fi
shift

# Backward compatibility for the old AFL -I contract:
# ntfy-hook.sh <harness_path> <fuzz_out>
case "$message_type" in
    function-missing|new-crash|real-crash|afl-stopped) ;;
    *)
        set -- "$message_type" "$@"
        message_type="new-crash"
        ;;
esac

harness_path="${1:-}"
fuzz_out="${2:-}"
detail="${3:-}"

if [ -z "$harness_path" ] || [ -z "$fuzz_out" ]; then
    usage
    exit 1
fi

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

case "$message_type" in
    new-crash)
        title="new crash: $harness_name"
        priority="default"
        tags="test_tube"
        ;;
    function-missing)
        title="function missing: $harness_name"
        priority="low"
        tags="construction"
        ;;
    real-crash)
        title="real crash: $harness_name"
        priority="high"
        tags="rotating_light"
        ;;
    afl-stopped)
        title="AFL stopped: $harness_name"
        priority="default"
        tags="stop_sign"
        ;;
esac

message="type=$message_type
harness=$harness_path
out=$fuzz_out
crashes=$crash_count
latest=$latest_crash
host=$(hostname)"

if [ -n "$detail" ]; then
    message="$message
detail=$detail"
fi

curl -fsS \
    -H "Authorization: Bearer $NTFY_TOKEN" \
    -H "Title: $title" \
    -H "Priority: $priority" \
    -H "Tags: $tags" \
    -d "$message" \
    "$ntfy_url/$NTFY_TOPIC"
