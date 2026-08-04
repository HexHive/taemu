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
warn() { echo "${C_YEL}[!!]${C_RST} $*"; }
die()  { echo "${C_RED}[--]${C_RST} $*" >&2; exit 1; }

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

ae_redis_up() {
    if (echo >"/dev/tcp/$AE_REDIS_HOST/$AE_REDIS_PORT") 2>/dev/null; then
        return 0
    fi
    return 1
}

ae_require_redis() {
    ae_redis_up && return 0
    log "starting redis ..."
    docker compose -f "$REPO_DIR/docker-compose.redis.yml" up -d >/dev/null 2>&1 \
        || die "could not start redis (docker compose -f docker-compose.redis.yml up -d)"
    for _ in $(seq 20); do
        ae_redis_up && { ok "redis is up"; return 0; }
        sleep 1
    done
    die "redis did not come up on $AE_REDIS_HOST:$AE_REDIS_PORT"
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
