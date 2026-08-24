#!/usr/bin/env bash
# Oversharing - artifact evaluation driver.
#
# All experiments run inside docker. This script is the only thing executed on
# the host: it builds the two images and then re-executes itself inside the
# controller container (ta_emu_ae_ctl), which has the docker client, the
# evaluation scripts and the plotting stack. The controller starts the
# per-TA emulator containers (ta_emu_ae) as siblings through the forwarded
# docker socket.
#
#   ./ae.sh setup          build the images and start redis
#   ./ae.sh list           show all experiments
#   ./ae.sh <experiment>   run one experiment
#   ./ae.sh all            run the full (scaled-down) evaluation
#
# Results are written to ae/results/<experiment>/.
set -uo pipefail

AE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$AE_DIR/.." && pwd)"

# shellcheck source=lib/common.sh
. "$AE_DIR/lib/common.sh"

CTL_IMAGE="${AE_CTL_IMAGE:-ta_emu_ae_ctl}"

EXPERIMENTS=(
  "e1_automatic_df_detection:Section III - the pipeline: Exploration, Fetch-Anchored Fuzzing, Distillation, then Table I and Figures 4 and 5"
  "e2_vulns:Table II - reproduce the six TOCTTOU vulnerabilities"
  "e3_rust:Table IV - double fetches in Rust TAs"
)

usage() {
    cat <<EOF
Oversharing artifact evaluation

  ./ae.sh setup              build the docker images and start redis
  ./ae.sh list               list the experiments
  ./ae.sh <experiment>       run a single experiment
  ./ae.sh all                run every experiment (scaled-down budgets)
  ./ae.sh shell              interactive shell in the controller container
  ./ae.sh clean              delete everything the experiments produced
                             (ae/results and all fuzzing state)

Experiments:
EOF
    for e in "${EXPERIMENTS[@]}"; do
        printf "  %-26s %s\n" "${e%%:*}" "${e#*:}"
    done
    cat <<EOF

Scaling (see ae/config.env) - the defaults size themselves to this machine:
  AE_JOBS=$AE_JOBS parallel emulator containers (${AE_JOBS_REASON:-})
  AE_SUBSET=$([ "$AE_SUBSET" = all ] && printf 'all - 27 harnesses, the 30 TAs of Table I' \
              || printf '%s harness(es)' "$(printf '%s' "$AE_SUBSET" | wc -w)")
  AE_EXPLORE_TIME=$AE_EXPLORE_TIME s of Exploration per TA, x$AE_EXPLORE_REPS (paper: 86400 x 5)
  AE_FAF_TIME=$AE_FAF_TIME s of Fetch-Anchored Fuzzing per snapshot (paper: 900)
  AE_FAF_MAX_SNAPSHOTS=$AE_FAF_MAX_SNAPSHOTS snapshots fuzzed per TA (paper: all)

  AE_SCALE=quick           five TAs, short budgets (~1 h in total)
  AE_SCALE=paper           the paper's budgets (weeks of CPU time)
EOF
}

in_controller() { [ -f /.ae_controller ]; }

build_images() {
    log "building the emulator image ($AE_IMAGE) ..."
    DOCKER_BUILDKIT=1 docker build --network host -t "$AE_IMAGE" "$REPO_DIR" \
        || die "failed to build $AE_IMAGE"
    log "building the controller image ($CTL_IMAGE) ..."
    DOCKER_BUILDKIT=1 docker build --network host \
        --build-arg "BASE_IMAGE=$AE_IMAGE" \
        -f "$AE_DIR/Dockerfile" -t "$CTL_IMAGE" "$REPO_DIR" \
        || die "failed to build $CTL_IMAGE"
    ok "images built"
}

# Re-execute this script inside the controller container. The repository is
# mounted at its *host* path so that the emulator containers started from
# within can use the same path in their own bind mounts.
run_in_controller() {
    # -t only when we actually have a terminal, so the driver also works from
    # scripts, CI and `nohup ./ae.sh all &`.
    local tty=()
    [ -t 0 ] && [ -t 1 ] && tty=(-it)
    docker run --rm "${tty[@]}" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$REPO_DIR:$REPO_DIR" \
        -v /dev/shm:/dev/shm --ipc=host \
        --network host \
        -w "$REPO_DIR" \
        -e "TAEMU_ROOT=$REPO_DIR" \
        -e "TAEMU_IMAGE=$AE_IMAGE" \
        -e "AE_IMAGE=$AE_IMAGE" \
        -e "AE_JOBS=$AE_JOBS" \
        -e "AE_SCALE=${AE_SCALE:-ae}" \
        -e "AE_EXPLORE_TIME=$AE_EXPLORE_TIME" \
        -e "AE_EXPLORE_REPS=$AE_EXPLORE_REPS" \
        -e "AE_FAF_TIME=$AE_FAF_TIME" \
        -e "AE_FAF_MAX_SNAPSHOTS=$AE_FAF_MAX_SNAPSHOTS" \
        -e "AE_DEDUP_LIMIT=$AE_DEDUP_LIMIT" \
        -e "AE_SUBSET=$AE_SUBSET" \
        -e "PYTHONPATH=$REPO_DIR/ae/lib:$REPO_DIR/eval" \
        -e "AE_POOL_WORKERS=${AE_POOL_WORKERS:-}" \
        -e "AE_GRAPH_WORKERS=${AE_GRAPH_WORKERS:-}" \
        -e "AE_ANNOTATE_WORKERS=${AE_ANNOTATE_WORKERS:-}" \
        -e "AE_GRAPH_WORKER_MB=${AE_GRAPH_WORKER_MB:-}" \
        -e "AE_ANNOTATE_WORKER_MB=${AE_ANNOTATE_WORKER_MB:-}" \
        -e "AE_REDIS_HOST=$AE_REDIS_HOST" -e "AE_REDIS_PORT=$AE_REDIS_PORT" \
        -e "REDIS_HOST=$AE_REDIS_HOST" -e "REDIS_PORT=$AE_REDIS_PORT" \
        -e "TAEMU_KEEP_REDIS=1" \
        -e "AE_HOST_UID=$(id -u)" -e "AE_HOST_GID=$(id -g)" \
        "$CTL_IMAGE" bash -c "touch /.ae_controller; $*; rc=\$?; \
            chown -R \$AE_HOST_UID:\$AE_HOST_GID '$AE_DIR' 2>/dev/null; \
            for d in '$REPO_DIR'/*/harness/ae_*; do \
                [ -e \"\$d\" ] && chown -R \$AE_HOST_UID:\$AE_HOST_GID \"\$d\" 2>/dev/null; \
            done; exit \$rc"
}

cmd_setup() {
    ae_banner "Setup"
    command -v docker >/dev/null || die "docker is required"
    build_images
    ae_require_redis
    ae_check_redis_from_container
    ok "ready - ./ae.sh list shows the experiments"
}

cmd_shell() { run_in_controller "bash"; }

main() {
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        ""|-h|--help|help) usage ;;
        list) usage ;;
        setup) cmd_setup ;;
        shell) cmd_shell ;;
        all)
            ae_require_image; ae_require_redis
            for e in "${EXPERIMENTS[@]}"; do
                local name="${e%%:*}"
                ae_banner "${e#*:}"
                run_in_controller "python3 '$AE_DIR/experiments/${name}.py'" \
                    || err "$name reported failures (see ae/results/$name)"
            done
            run_in_controller "python3 '$AE_DIR/experiments/report.py'"
            ;;
        e*)
            local script="$AE_DIR/experiments/${cmd}.py"
            [ -f "$script" ] || die "unknown experiment '$cmd' (try ./ae.sh list)"
            ae_require_image; ae_require_redis
            ae_banner "$cmd"
            run_in_controller "python3 '$script' $*"
            ;;
        report) run_in_controller "python3 '$AE_DIR/experiments/report.py'" ;;
        clean)
            # Everything the experiments produce: ae/results, the ae_* working
            # harnesses, and the fuzzing state of every harness - AFL queues and
            # coverage (out/), recorded double-fetch seeds (in/), snapshots
            # (df_fuzz/), the recorder's bookkeeping (record_meta/) and logs/.
            #
            # None of this is shipped with the artifact: a fresh checkout has
            # none of these directories and every one of them is recreated by
            # ./ae.sh all. Nothing that is part of the artifact is touched.
            log "removing ae/results and the ae_* working harnesses ..."
            run_in_controller "rm -rf '$AE_DIR/results' '$REPO_DIR'/*/harness/ae_e*_*"
            log "removing the fuzzing state of every harness ..."
            # NOTE: only the *generated* parts of in/ are removed. This
            # repository tracks curated seed corpora under */harness/*/in/
            # (the AE snapshot this script came from had none), so wiping the
            # whole directory would delete committed inputs.
            run_in_controller "rm -rf \
                '$REPO_DIR'/*/harness/*/in/suspicious_inputs \
                '$REPO_DIR'/*/harness/*/in/suspicious_inputs_replay \
                '$REPO_DIR'/*/harness/*/out \
                '$REPO_DIR'/*/harness/*/df_fuzz '$REPO_DIR'/*/harness/*/record_meta \
                '$REPO_DIR'/*/harness/*/logs"
            run_in_controller "find '$REPO_DIR' -path '*/harness/*/in/run:id:*' -delete" 
            # Droppings outside the harnesses: the TA copies fuzz.sh leaves in
            # emulator/rootfs (the loader stubs there are tracked and stay),
            # the secure-storage objects a TA created, the coverage file list
            # and the plotting log, and python bytecode.
            log "removing the emulator and evaluation droppings ..."
            run_in_controller "rm -rf \
                '$REPO_DIR'/emulator/rootfs/*.ta '$REPO_DIR'/emulator/rootfs/*.json \
                '$REPO_DIR'/emulator/rootfs/id:* '$REPO_DIR'/emulator/ql-emulator.log* \
                '$REPO_DIR'/emulator/emulate/files/*/*-, \
                '$REPO_DIR'/.suspicious_inputs_cov_files.txt \
                '$REPO_DIR'/eval/graphs/*.log; \
                find '$REPO_DIR' -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null; \
                true"
            docker ps -a --format '{{.Names}}' | grep -E '^emu_' \
                | xargs -r docker rm -f >/dev/null 2>&1
            ok "cleaned"
            ;;
        *) die "unknown command '$cmd' (try ./ae.sh --help)" ;;
    esac
}

main "$@"
