#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

HARNESS_ROOT="${HARNESS_ROOT:-qsee_nongp/harness}"
OUT_SUFFIX="${OUT_SUFFIX:-}"
SESSION_NAME="${SESSION_NAME:-qsee-nongp-fuzz}"
CONTAINER_PREFIX="${CONTAINER_PREFIX:-qsee-nongp-fuzz-}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not available on PATH"
    exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux is not available on PATH"
    exit 1
fi

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    echo "tmux session already exists: $SESSION_NAME"
    echo "Attach with: tmux attach -t $SESSION_NAME"
    exit 1
fi

if [ ! -d "$HARNESS_ROOT" ]; then
    echo "Harness root not found: $HARNESS_ROOT"
    exit 1
fi

mapfile -t harnesses < <(
    find "$HARNESS_ROOT" -mindepth 1 -maxdepth 1 -type d | sort
)

if [ "${#harnesses[@]}" -eq 0 ]; then
    echo "No harness directories found in $HARNESS_ROOT"
    exit 1
fi

quote_cmd() {
    printf '%q ' "$@"
}

started=0
skipped=0

for harness in "${harnesses[@]}"; do
    name="$(basename "$harness")"

    if [ ! -f "$harness/harness.py" ]; then
        echo "Skipping $name: missing harness.py"
        skipped=$((skipped + 1))
        continue
    fi

    [[ -n "$(ls -1 "$harness"/*.ta "$harness"/*.elf 2>/dev/null)" ]] || {
        echo "Skipping $name: no TA or ELF found"
        skipped=$((skipped + 1))
        continue
    }

    safe_name="$(printf '%s' "$name" | tr -c '[:alnum:]_.-' '-')"
    container_name="${CONTAINER_PREFIX}${safe_name}"
    container_harness="../${harness}"

    docker_cmd=(
        docker compose run --rm
        --name "$container_name"
        -e "AFL_NO_UI=${AFL_NO_UI:-1}"
        -e "TAEMU_CRASH_NOTIMPL=${TAEMU_CRASH_NOTIMPL:-1}"
    )

    if [ -n "${FUZZTIME:-}" ]; then
        docker_cmd+=(-e "FUZZTIME=$FUZZTIME")
    fi

    if [ -n "${FUZZ_TIMEOUT:-}" ]; then
        docker_cmd+=(-e "FUZZ_TIMEOUT=$FUZZ_TIMEOUT")
    fi

    docker_cmd+=(emulator ./fuzz.sh "$container_harness")

    if [ -n "$OUT_SUFFIX" ]; then
        docker_cmd+=(--out_suffix "$OUT_SUFFIX")
    fi

    fuzz_cmd="$(quote_cmd "${docker_cmd[@]}")"
    window_cmd="$fuzz_cmd; status=\$?; echo; echo \"fuzz.sh exited with status \$status\"; exec bash"

    echo "Starting tmux window: $name"
    if [ "$started" -eq 0 ]; then
        tmux new-session -d -s "$SESSION_NAME" -n "$name" -c "$SCRIPT_DIR" "$window_cmd"
    else
        tmux new-window -t "$SESSION_NAME" -n "$name" -c "$SCRIPT_DIR" "$window_cmd"
    fi
    started=$((started + 1))
done

if [ "$started" -eq 0 ]; then
    echo "No runnable harnesses found. Skipped $skipped harnesses."
    exit 1
fi

echo "Started $started fuzzers in tmux session '$SESSION_NAME'. Skipped $skipped harnesses."
echo "Attach with: tmux attach -t $SESSION_NAME"
