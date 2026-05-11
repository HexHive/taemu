#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUT_SUFFIX="${OUT_SUFFIX:-}"
SESSION_NAME="${SESSION_NAME:-qsee-nongp-fuzz}"
CONTAINER_PREFIX="${CONTAINER_PREFIX:-qsee-nongp-fuzz-}"
CORE_START="${CORE_START:-30}"
TRIAGE_HOOK="${TRIAGE_HOOK:-/srv/medic/auto-triage.sh}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ta_emu}"

usage() {
    echo "usage: $0 -d <harness_root>"
    echo "usage: $0 <harness_dir> [<harness_dir> ...]"
}

HARNESS_ROOT=""

while getopts ":d:" opt; do
    case "$opt" in
        d) HARNESS_ROOT="${OPTARG%/}" ;;
        *)
            usage
            exit 1
            ;;
    esac
done

shift $((OPTIND - 1))

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

if [ -n "$HARNESS_ROOT" ] && [ "$#" -gt 0 ]; then
    echo "Specify either -d <harness_root> or an explicit harness list, not both"
    exit 1
fi

if [ "$#" -gt 0 ]; then
    harnesses=()
    for harness in "$@"; do
        harness="${harness%/}"
        harnesses+=("$harness")
    done
elif [ -n "$HARNESS_ROOT" ]; then
    if [ ! -d "$HARNESS_ROOT" ]; then
        echo "Harness root not found: $HARNESS_ROOT"
        exit 1
    fi
    mapfile -t harnesses < <(
        find "$HARNESS_ROOT" -mindepth 1 -maxdepth 1 -type d | sort
    )
else
    usage
    exit 1
fi

if [ "${#harnesses[@]}" -eq 0 ]; then
    echo "No harness directories found"
    exit 1
fi

quote_cmd() {
    printf '%q ' "$@"
}

quote_one() {
    printf '%q' "$1"
}

ntfy_vars_set=0
if [ -n "${NTFY_TOKEN:-}" ] || [ -n "${NTFY_TOPIC:-}" ] || [ -n "${NTFY_URL:-}" ]; then
    if [ -n "${NTFY_TOKEN:-}" ] && [ -n "${NTFY_TOPIC:-}" ] && [ -n "${NTFY_URL:-}" ]; then
        ntfy_vars_set=1
    else
        echo "NTFY_* variables must be all set or all unset; skipping all ntfy forwarding"
    fi
fi

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
    container_fuzz_out="${container_harness}/out${OUT_SUFFIX}"
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
        # --privileged
        --user root
        # These ones get forwarded.
        -e "AFL_NO_UI" -e "AFL_DEBUG"
        # These ones get set.
        -e "AFL_NO_AFFINITY=1"
        -e "TAEMU_CRASH_NOTIMPL=1"
    )

    if [ "$ntfy_vars_set" -eq 1 ]; then
        docker_cmd+=(-e "NTFY_TOKEN=$NTFY_TOKEN")
        docker_cmd+=(-e "NTFY_TOPIC=$NTFY_TOPIC")
        docker_cmd+=(-e "NTFY_URL=$NTFY_URL")
    fi

    if [ -n "${FUZZTIME:-}" ]; then
        docker_cmd+=(-e "FUZZTIME=$FUZZTIME")
    fi

    if [ -n "${FUZZ_TIMEOUT:-}" ]; then
        docker_cmd+=(-e "FUZZ_TIMEOUT=$FUZZ_TIMEOUT")
    fi

    container_shell="./fuzz.sh $(quote_one "$container_harness") -I $(quote_one "$TRIAGE_HOOK")"
    if [ -n "$OUT_SUFFIX" ]; then
        container_shell="$container_shell --out_suffix $(quote_one "$OUT_SUFFIX")"
    fi
    container_shell="$container_shell; status=\$?; /srv/medic/ntfy-hook.sh afl-stopped $(quote_one "$container_harness") $(quote_one "$container_fuzz_out") \"exit_status=\$status\"; echo; echo \"fuzz.sh exited with status \$status\"; exec bash -i"

    docker_cmd+=("$DOCKER_IMAGE" bash -ic "set -x; $container_shell")

    window_cmd="$(quote_cmd "${docker_cmd[@]}")"
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
