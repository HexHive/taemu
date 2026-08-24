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

# ae_is_wsl -- running under the Windows Subsystem for Linux?
ae_is_wsl() { grep -qi microsoft /proc/version 2>/dev/null; }

# ae_is_docker_desktop -- is the docker daemon Docker Desktop's, rather than a
# Docker Engine installed inside this distribution? Desktop runs the daemon in
# its own utility VM, which is what makes --network host and the loopback
# behave differently from a native install.
ae_is_docker_desktop() {
    docker info --format '{{.OperatingSystem}}{{.Name}}' 2>/dev/null \
        | grep -qi 'docker desktop'
}

# ae_wsl_hint -- WSL-specific advice, printed only where it applies.
ae_wsl_hint() {
    ae_is_wsl || return 0
    err ""
    err "this looks like WSL. two things bite here:"
    err "  * the compose plugin: Ubuntu's docker.io package does not pull it in."
    err "      sudo apt-get install docker-compose-plugin"
    err "  * Docker Desktop's WSL integration: the daemon runs in Desktop's own"
    err "    VM, so the experiments' --network host containers do not share this"
    err "    distribution's loopback. we recommend Docker Engine installed"
    err "    *inside* the distribution instead - docs.docker.com/engine/install/ubuntu"
    err "    (then: sudo service docker start, after every WSL restart)."
    err "  a windows-side service on 6379 also blocks the publish; either stop it"
    err "  or run with AE_REDIS_PORT=6380."
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

# ae_redis_run -- start redis without compose, as a plain container.
# The evaluation only needs a redis server on the published port; compose is a
# convenience, not a requirement. This is the fallback for hosts where the
# compose plugin is missing, too old for the file, or fails for its own
# reasons.
ae_redis_run() {
    local out
    # A container from an earlier run may exist but be stopped.
    if docker container inspect ta_emulator_redis >/dev/null 2>&1; then
        out="$(docker start ta_emulator_redis 2>&1)" && return 0
        [ -n "$out" ] && printf '%s\n' "$out" >&2
        # Stale container (wrong port, wrong image): remove and recreate.
        docker rm -f ta_emulator_redis >/dev/null 2>&1
    fi
    if ! out="$(docker run -d --name ta_emulator_redis \
            -p "$AE_REDIS_PORT:6379" \
            -v ta_emulator_redis_data:/data \
            --restart unless-stopped \
            redis:7-alpine redis-server --appendonly yes 2>&1)"; then
        printf '%s\n' "${out:-(docker run produced no output)}" >&2
        return 1
    fi
    return 0
}

ae_require_redis() {
    ae_redis_up && return 0
    log "starting redis ..."
    local out
    # Only the "redis" service: redis-commander is a browser UI no experiment
    # uses, and a failure to pull it must not stop the evaluation.
    if ! out="$(ae_compose -f "$REPO_DIR/docker-compose.redis.yml" up -d redis 2>&1)"; then
        printf '%s\n' "${out:-(docker compose produced no output)}" >&2
        warn "docker compose could not start redis, falling back to docker run"
        err "docker compose could not start redis - starting it with plain 'docker run'"
        ae_redis_run || { ae_wsl_hint; die "could not start redis (see the errors above)"; }
    fi
    for _ in $(seq 20); do
        ae_redis_up && { ok "redis is up"; return 0; }
        sleep 1
    done
    # The container came up but nothing is listening on the host port. Say what
    # docker thinks the state is - that is what tells the two cases apart.
    err "redis did not come up on $AE_REDIS_HOST:$AE_REDIS_PORT"
    ae_compose -f "$REPO_DIR/docker-compose.redis.yml" ps >&2 2>/dev/null
    docker ps -a --filter name=ta_emulator_redis >&2 2>/dev/null
    docker logs --tail 20 ta_emulator_redis >&2 2>&1
    ae_wsl_hint
    die "set AE_REDIS_HOST/AE_REDIS_PORT if redis runs elsewhere"
}

# ae_check_redis_from_container -- the check that matters.
# Every experiment runs its emulator with `docker run --network host` and has it
# reach redis over the loopback. That the *host* can reach the published port
# says nothing about whether those containers can: under Docker Desktop the
# containers live in Desktop's utility VM and share its network namespace, not
# this one. Verify it now, in setup, rather than an hour into an experiment.
ae_check_redis_from_container() {
    ae_have_image || return 0
    docker run --rm --network host "$AE_IMAGE" \
        bash -c "exec 3<>/dev/tcp/$AE_REDIS_HOST/$AE_REDIS_PORT" >/dev/null 2>&1 \
        && { ok "redis is reachable from the emulator containers"; return 0; }

    err "redis is up on the host, but the emulator containers cannot reach it"
    err "at $AE_REDIS_HOST:$AE_REDIS_PORT over --network host."
    if ae_is_docker_desktop; then
        err "the daemon is Docker Desktop's, which runs containers in its own VM."
        err "either enable Settings > Resources > Network > 'Enable host networking',"
        err "or - what we recommend - install Docker Engine inside this"
        err "distribution: docs.docker.com/engine/install/ubuntu"
    else
        err "check that nothing (firewall, netfilter policy) blocks the loopback,"
        err "or point the experiments elsewhere with AE_REDIS_HOST/AE_REDIS_PORT."
    fi
    ae_wsl_hint
    die "the experiments would fail at their first memory record"
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
