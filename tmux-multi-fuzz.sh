#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

HARNESS_ROOT="${HARNESS_ROOT:-qsee_nongp/harness}"
OUT_SUFFIX="${OUT_SUFFIX:-}"
SESSION_NAME="${SESSION_NAME:-qsee-nongp-fuzz}"
CONTAINER_PREFIX="${CONTAINER_PREFIX:-qsee-nongp-fuzz-}"
CORE_START="${CORE_START:-30}"
TRIAGE_HOOK="${TRIAGE_HOOK:-/srv/medic/ntfy-hook.sh}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ta_emu}"

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

quote_one() {
    printf '%q' "$1"
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

    safe_name="$(printf '%s' "$name" | tr -c '[:alnum:]_.-' '-')"
    container_name="${CONTAINER_PREFIX}${safe_name}${OUT_SUFFIX:+-$OUT_SUFFIX}"
    container_harness="../${harness}"
    core=$((CORE_START + started))

    docker_cmd=(
        docker run --rm
        -it
        --name "$container_name"
        --cpuset-cpus "$core"
        --network host
        --volume "$SCRIPT_DIR:/srv"
        --workdir /srv/emulator
        --shm-size 100g
        --ipc host
        --privileged
        --user root
        -e "AFL_NO_UI"
        -e "AFL_NO_AFFINITY=1"
        -e "TAEMU_CRASH_NOTIMPL=${TAEMU_CRASH_NOTIMPL:-1}"
    )

    if [ -n "${NTFY_TOKEN:-}" ]; then
        docker_cmd+=(-e "NTFY_TOKEN=$NTFY_TOKEN")
    fi
    if [ -n "${NTFY_TOPIC:-}" ]; then
        docker_cmd+=(-e "NTFY_TOPIC=$NTFY_TOPIC")
    fi
    if [ -n "${NTFY_URL:-}" ]; then
        docker_cmd+=(-e "NTFY_URL=$NTFY_URL")
    fi

    if [ -n "${FUZZTIME:-}" ]; then
        docker_cmd+=(-e "FUZZTIME=$FUZZTIME")
    fi

    if [ -n "${FUZZ_TIMEOUT:-}" ]; then
        docker_cmd+=(-e "FUZZ_TIMEOUT=$FUZZ_TIMEOUT")
    fi

    docker_cmd+=("$DOCKER_IMAGE" ./fuzz.sh "$container_harness" -I "$TRIAGE_HOOK")

    if [ -n "$OUT_SUFFIX" ]; then
        docker_cmd+=(--out_suffix "$OUT_SUFFIX")
    fi

    fuzz_cmd="$(quote_cmd "${docker_cmd[@]}")"
    shell_body="$fuzz_cmd; status=\$?; echo; echo \"fuzz.sh exited with status \$status\"; exec bash -i"
    window_cmd="bash -ic $(quote_one "$shell_body")"
    echo "Starting tmux window: $name on CPU $core"
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
