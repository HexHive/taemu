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
#   ./ae.sh setup          build images, start redis, smoke-test the emulator
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
  "e1_exploration:Stage 1 - Exploration: find overlapped fetches in TAs"
  "e2_faf:Stage 2 - Fetch-Anchored Fuzzing on the snapshots of Stage 1"
  "e3_distillation:Stage 3 - Distillation: keep only shared-memory crashes"
  "e4_table1:Table I - summary of a campaign (run E1-E3 first, then --source ae)"
  "e5_vulns:Table II - reproduce the six TOCTTOU vulnerabilities"
  "e6_rust:Table IV - double fetches in Rust TAs"
  "e7_reshaping:Table V - executions that trigger a double fetch"
  "e8_figures:Figures 4 and 5 - coverage of Exploration and of FAF"
  "e9_mitigation:Section VII - OP-TEE opt-in shared memory mitigation"
)

usage() {
    cat <<EOF
Oversharing artifact evaluation

  ./ae.sh setup              build the docker images, start redis, self-test
  ./ae.sh list               list the experiments
  ./ae.sh <experiment>       run a single experiment
  ./ae.sh all                run every experiment (scaled-down budgets)
  ./ae.sh shell              interactive shell in the controller container

Experiments:
EOF
    for e in "${EXPERIMENTS[@]}"; do
        printf "  %-16s %s\n" "${e%%:*}" "${e#*:}"
    done
    cat <<EOF

Scaling (see ae/config.env):
  AE_JOBS=$AE_JOBS                 parallel emulator containers
  AE_EXPLORE_TIME=$AE_EXPLORE_TIME     seconds of Exploration per TA (paper: 86400 x 5)
  AE_FAF_TIME=$AE_FAF_TIME            seconds of Fetch-Anchored Fuzzing per snapshot (paper: 900)
  AE_SCALE=paper           use the paper's budgets instead (weeks of CPU time)
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
        -e "AE_SUBSET=$AE_SUBSET" \
        -e "AE_POC_ATTEMPTS=${AE_POC_ATTEMPTS:-15}" \
        -e "PYTHONPATH=$REPO_DIR/ae/lib:$REPO_DIR/eval" \
        -e "TAEMU_KEEP_REDIS=1" \
        -e "AE_HOST_UID=$(id -u)" -e "AE_HOST_GID=$(id -g)" \
        "$CTL_IMAGE" bash -c "touch /.ae_controller; $*; rc=\$?; \
            chown -R \$AE_HOST_UID:\$AE_HOST_GID '$AE_DIR' 2>/dev/null; \
            [ -d '$REPO_DIR/swarm/target' ] && \
                chown -R \$AE_HOST_UID:\$AE_HOST_GID '$REPO_DIR/swarm/target' 2>/dev/null; \
            for d in '$REPO_DIR'/*/harness/ae_*; do \
                [ -e \"\$d\" ] && chown -R \$AE_HOST_UID:\$AE_HOST_GID \"\$d\" 2>/dev/null; \
            done; exit \$rc"
}

cmd_setup() {
    ae_banner "Setup"
    command -v docker >/dev/null || die "docker is required"
    build_images
    ae_require_redis
    log "building the campaign orchestrator (swarm) ..."
    run_in_controller "cd '$REPO_DIR/swarm' && cargo build --release 2>&1 | tail -3" \
        || warn "swarm build failed - e2/e3 fall back to the built-in scheduler"
    ae_banner "Self-test: emulate a TA and replay one Exploration seed"
    run_in_controller "python3 '$AE_DIR/experiments/e0_selftest.py'"
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
            # The first four experiments form one campaign: each stage consumes
            # what the previous one produced, and Table I summarises that run.
            local args
            for e in "${EXPERIMENTS[@]}"; do
                local name="${e%%:*}"
                case "$name" in
                    e2_faf)          args="--from exploration" ;;
                    e3_distillation) args="--from faf" ;;
                    e4_table1)       args="--source ae" ;;
                    *)               args="" ;;
                esac
                ae_banner "${e#*:}"
                run_in_controller "python3 '$AE_DIR/experiments/${name}.py' $args" \
                    || warn "$name reported failures (see ae/results/$name)"
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
            log "removing the working harnesses of E2/E3/E4 and ae/results ..."
            run_in_controller "rm -rf '$AE_DIR/results' '$REPO_DIR'/*/harness/ae_e*_*"
            docker ps -a --format '{{.Names}}' | grep -E '^(emu_|swarm_emu_)' \
                | xargs -r docker rm -f >/dev/null 2>&1
            ok "cleaned"
            ;;
        *) die "unknown command '$cmd' (try ./ae.sh --help)" ;;
    esac
}

main "$@"
