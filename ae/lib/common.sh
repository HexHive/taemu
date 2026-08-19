#!/usr/bin/env bash
# Shared helpers for the artifact-evaluation experiments.
set -uo pipefail

AE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$AE_DIR/.." && pwd)"
RESULTS_DIR="$AE_DIR/results"

# shellcheck source=/dev/null
. "$AE_DIR/config.env"

C_RED=$'\e[1;31m'; C_GRN=$'\e[1;32m'; C_YEL=$'\e[1;33m'; C_BLU=$'\e[1;34m'; C_RST=$'\e[0m'

log()  { echo "${C_BLU}[ae]${C_RST} $*"; }
ok()   { echo "${C_GRN}[ok]${C_RST} $*"; }
err()  { echo "${C_RED}[--]${C_RST} $*"; }
die()  { echo "${C_RED}[--]${C_RST} $*" >&2; exit 1; }

# Advisory notes are not printed - an experiment's output is its table and its
# checks. They go to ae/results/notes.log, next to the numbers they qualify.
warn() { mkdir -p "$RESULTS_DIR"; echo "$*" >> "$RESULTS_DIR/notes.log"; }

# ae_have_image -- does the emulator image exist?
ae_have_image() { docker image inspect "$AE_IMAGE" >/dev/null 2>&1; }

ae_require_image() {
    ae_have_image || die "docker image '$AE_IMAGE' is missing - run ./ae.sh setup first"
}

# ae_docker <shell command ...>
# Runs a command inside a throw-away emulator container. The repository is
# bind-mounted at /srv, the working directory is /srv/emulator, so the
# emulator's own scripts (fuzz.sh, df_fuzz.sh, df_validate.sh) can be called
# with paths relative to /srv/emulator (i.e. "../mitee/harness/...").
ae_docker() {
    docker run --rm --network host \
        -v "$REPO_DIR:/srv" -w /srv/emulator \
        -v /dev/shm:/dev/shm --ipc=host \
        -e "REDIS_HOST=$AE_REDIS_HOST" -e "REDIS_PORT=$AE_REDIS_PORT" \
        ${AE_DOCKER_EXTRA:-} \
        "$AE_IMAGE" bash -c "$*"
}

# ae_compose <args ...> -- compose v2 (the plugin) or, failing that, v1.
ae_compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        err "neither 'docker compose' (v2 plugin) nor 'docker-compose' (v1) is installed."
        err "on Debian/Ubuntu, including Ubuntu under WSL:"
        err "    sudo apt-get install docker-compose-plugin"
        err "(the distribution's docker.io package does not pull the plugin in;"
        err " see docs.docker.com/engine/install/ubuntu for docker's own repository)"
        return 127
    fi
}

# The recorder reaches redis over the published port, so probe the loopback and
# not the container: an "up" container whose port is not reachable is not up as
# far as the emulator is concerned. localhost can resolve to ::1 first while the
# port is only published on 0.0.0.0 (the common case under WSL), so try the
# literal v4 and v6 loopbacks as well.
ae_redis_up() {
    local h
    for h in "$AE_REDIS_HOST" 127.0.0.1 ::1; do
        (echo >"/dev/tcp/$h/$AE_REDIS_PORT") 2>/dev/null || continue
        [ "$h" = "$AE_REDIS_HOST" ] || {
            warn "redis: $AE_REDIS_HOST:$AE_REDIS_PORT was not reachable, using $h"
            AE_REDIS_HOST="$h"
        }
        return 0
    done
    return 1
}

ae_require_redis() {
    ae_redis_up && return 0
    log "starting redis ..."
    local out
    if ! out="$(ae_compose -f "$REPO_DIR/docker-compose.redis.yml" up -d 2>&1)"; then
        [ -n "$out" ] && printf '%s\n' "$out" >&2
        die "could not start redis (docker compose -f docker-compose.redis.yml up -d)"
    fi
    for _ in $(seq 20); do
        ae_redis_up && { ok "redis is up"; return 0; }
        sleep 1
    done
    # The container came up but nothing is listening on the host port. Say what
    # docker thinks the state is - that is what tells the two cases apart.
    err "redis did not come up on $AE_REDIS_HOST:$AE_REDIS_PORT"
    ae_compose -f "$REPO_DIR/docker-compose.redis.yml" ps >&2 2>/dev/null
    docker logs --tail 20 ta_emulator_redis >&2 2>&1
    die "set AE_REDIS_HOST/AE_REDIS_PORT if redis runs elsewhere"
}

# ae_result_dir <experiment> -- create and echo the result directory
ae_result_dir() {
    local d="$RESULTS_DIR/$1"
    mkdir -p "$d"
    echo "$d"
}

# ae_banner <title>
ae_banner() {
    echo
    echo "${C_BLU}================================================================${C_RST}"
    echo "${C_BLU} $*${C_RST}"
    echo "${C_BLU}================================================================${C_RST}"
}
