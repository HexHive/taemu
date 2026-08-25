#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

harness_path="${1:-}"
fuzz_out="${2:-}"
report_dir="${3:-}"
explicit_artifact="${4:-}"

if [ -z "$harness_path" ] || [ -z "$fuzz_out" ]; then
    echo "triage-failed	reason=usage expected='<harness_path> <fuzz_out> [report_dir] [artifact]'"
    exit 0
fi

if [ -n "$report_dir" ]; then
    log_dir="$report_dir"
else
    log_dir="${SCRIPT_DIR}/logs/$(basename "$harness_path")"
fi

mkdir -p "$log_dir" "$log_dir/emulate-logs" "$log_dir/artifacts" "$log_dir/meta"

emit_result() {
    local type="$1"
    shift
    printf '%s\t%s\n' "$type" "$*"
}

artifact_kind() {
    case "$1" in
        */hangs|*/hangs.*|*/hangs/*|*/hangs.*/*) printf 'hangs' ;;
        *) printf 'crashes' ;;
    esac
}

find_newest_artifact() {
    find "$fuzz_out/default" -maxdepth 2 \
        \( -path "$fuzz_out/default/crashes" -o -path "$fuzz_out/default/crashes.*" -o \
           -path "$fuzz_out/default/hangs" -o -path "$fuzz_out/default/hangs.*" \) \
        -prune -type d -exec find {} -maxdepth 1 -type f ! -name 'README.txt' -printf '%T@ %p\n' \; 2>/dev/null |
        sort -nr |
        head -n 1 |
        cut -d' ' -f2-
}

if [ -n "$explicit_artifact" ]; then
    selected_artifact="$explicit_artifact"
else
    if [ ! -d "$fuzz_out/default" ]; then
        emit_result "triage-failed" "reason=no-afl-default-dir fuzz_out=$fuzz_out"
        exit 0
    fi
    selected_artifact="$(find_newest_artifact)"
fi

if [ -z "$selected_artifact" ]; then
    emit_result "triage-failed" "reason=no-artifact fuzz_out=$fuzz_out"
    exit 0
fi

if [ ! -f "$selected_artifact" ]; then
    emit_result "triage-failed" "reason=artifact-not-found artifact=$selected_artifact fuzz_out=$fuzz_out"
    exit 0
fi

kind="$(artifact_kind "$(dirname "$selected_artifact")")"
artifact_base="$(basename "$selected_artifact")"
artifact_parent="$(basename "$(dirname "$selected_artifact")")"
safe_parent="$(printf '%s' "$artifact_parent" | tr -c 'A-Za-z0-9_.:+=,@%-' '_')"
safe_artifact="$(printf '%s' "$artifact_base" | tr -c 'A-Za-z0-9_.:+=,@%-' '_')"
safe_base="${safe_parent}__${safe_artifact}"
artifact_copy_dir="$log_dir/artifacts/$kind"
mkdir -p "$artifact_copy_dir"
artifact_copy="$artifact_copy_dir/$safe_base"

if ! cp -f "$selected_artifact" "$artifact_copy"; then
    emit_result "triage-failed" "reason=copy-failed artifact=$selected_artifact copy=$artifact_copy"
    exit 0
fi

replay_log="$log_dir/emulate-logs/$safe_base.log"
metadata="$log_dir/meta/replay-results.tsv"
timeout_seconds="${REPLAY_FUZZ_TIMEOUT:-120}"

set +e
timeout -k 5 "$timeout_seconds" \
    "$SCRIPT_DIR/../emulator/fuzz.sh" "$harness_path" "$artifact_copy" --log_file "$replay_log" >"$replay_log" 2>&1
replay_status=$?
set -e

missing_functions="$(
    {
        (grep -E 'called, not implemented! lr: 0x[0-9a-fA-F]+' "$replay_log" || true) |
            sed -nE 's/^.*[[:space:]]([^[:space:]]+) called, not implemented! lr: 0x[0-9a-fA-F]+.*$/\1/p'
        (grep -E '=+\[lr: 0x[0-9a-fA-F]+\]' "$replay_log" || true) |
            awk '!/memory corruption detected/' |
            sed -nE 's/^.*=+\[lr: 0x[0-9a-fA-F]+\][[:space:]]+//p'
    } | sed '/^$/d' | sort -u
)"
setup_error=""
if grep -Eq 'Not running inside emulator Docker|Could not find TA|File .+ not found' "$replay_log"; then
    setup_error="replay-setup-error"
elif ! grep -q '^Replaying seed ' "$replay_log"; then
    setup_error="replay-did-not-start"
fi

if [ -n "$missing_functions" ]; then
    missing_summary="$(printf '%s\n' "$missing_functions" | paste -sd ',' -)"
    result_type="function-missing"
    detail="artifact=$selected_artifact copy=$artifact_copy kind=$kind replay_status=$replay_status missing=$missing_summary log=$replay_log"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$result_type" "$kind" "$selected_artifact" "$artifact_copy" "$replay_status" "$missing_summary" >>"$metadata"
    printf '%s\t\tartifact=%s copy=%s kind=%s replay_status=%s\n' "$missing_functions" "$selected_artifact" "$artifact_copy" "$kind" "$replay_status" >>"$log_dir/function-missing.txt"
elif [ -n "$setup_error" ]; then
    result_type="triage-failed"
    detail="reason=$setup_error artifact=$selected_artifact copy=$artifact_copy kind=$kind replay_status=$replay_status log=$replay_log"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$result_type" "$kind" "$selected_artifact" "$artifact_copy" "$replay_status" "$setup_error" >>"$metadata"
    printf 'reason=%s artifact=%s copy=%s kind=%s replay_status=%s log=%s\n' "$setup_error" "$selected_artifact" "$artifact_copy" "$kind" "$replay_status" "$replay_log" >>"$log_dir/triage-failed.txt"
elif [ "$kind" = "hangs" ] || [ "$replay_status" -eq 124 ] || [ "$replay_status" -eq 137 ]; then
    result_type="hang"
    detail="artifact=$selected_artifact copy=$artifact_copy kind=$kind replay_status=$replay_status log=$replay_log"
    printf '%s\t%s\t%s\t%s\t%s\t\n' "$result_type" "$kind" "$selected_artifact" "$artifact_copy" "$replay_status" >>"$metadata"
    printf 'artifact=%s copy=%s kind=%s replay_status=%s log=%s\n' "$selected_artifact" "$artifact_copy" "$kind" "$replay_status" "$replay_log" >>"$log_dir/hangs.txt"
else
    result_type="real-crash"
    detail="artifact=$selected_artifact copy=$artifact_copy kind=$kind replay_status=$replay_status log=$replay_log"
    printf '%s\t%s\t%s\t%s\t%s\t\n' "$result_type" "$kind" "$selected_artifact" "$artifact_copy" "$replay_status" >>"$metadata"
    printf 'artifact=%s copy=%s kind=%s replay_status=%s log=%s\n' "$selected_artifact" "$artifact_copy" "$kind" "$replay_status" "$replay_log" >>"$log_dir/real-crashes.txt"
fi

emit_result "$result_type" "$detail"
