#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# This script is invoked by afl-fuzz -I when a new crash is found.
# It classifies the newest crash by replaying it and forwards the resulting
# notification type to ntfy-hook.sh.
harness_path="${1:-}"
fuzz_out="${2:-}"

if [ -z "$harness_path" ] || [ -z "$fuzz_out" ]; then
    echo "usage: $0 <harness_path> <fuzz_out>"
    exit 1
fi

set +e
triage_result="$("$SCRIPT_DIR/replay-fuzz.sh" "$harness_path" "$fuzz_out" 2>&1)"
triage_status=$?
set -e

if [ "$triage_status" -ne 0 ]; then
    "$SCRIPT_DIR/ntfy-hook.sh" default-message "$harness_path" "$fuzz_out" "auto-triage failed: $triage_result"
    exit 0
fi

message_type="$(printf '%s\n' "$triage_result" | cut -f1)"
detail="$(printf '%s\n' "$triage_result" | cut -f2-)"

case "$message_type" in
    function-missing|real-crash)
        "$SCRIPT_DIR/ntfy-hook.sh" "$message_type" "$harness_path" "$fuzz_out" "$detail"
        ;;
    *)
        "$SCRIPT_DIR/ntfy-hook.sh" default-message "$harness_path" "$fuzz_out" "$triage_result"
        ;;
esac

exit 0
