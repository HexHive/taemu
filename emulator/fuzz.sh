#!/bin/bash

# Purpose: Run AFL++ fuzzing for a TA harness or replay a single seed through
# python3 -m emulate while collecting coverage/crash artifacts.
# Depends on: emulator Docker environment, AFL++ tools, python3 -m emulate,
# harness.py, TA .ta/.elf binary, adjacent .json/.yml metadata, and rootfs/.
# Input: Harness/TA path; either fuzz options (--out_suffix, --in_dir, --out_dir,
# --triage_hook, --triage_report_dir, --log_file) or a replay seed plus emulator args.

set -e

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_FORKSRV_INIT_TMOUT=1999999
export AFL_NO_FASTRESUME=1
export AFL_AUTORESUME=1
# NOTE: This is set in official afl docker image. not sure if it belongs here.

if [ -z "$1" ]; then 
    echo "usage: fuzzing ./fuzz.sh <path to ta|harness folder> [-I <new-crash hook command>] [--out_suffix <suffix>] [--in_dir <dir>] [--out_dir <dir>] [--triage_report_dir <dir>] [--log_file <file>]"
    echo "usage: replay seed ./fuzz.sh <path to ta|harness folder> <path to seed> [python-emulate-args...]"
    echo ""
    echo "env: FUZZTIME       seconds to fuzz for (default: until stopped)"
    echo "     FUZZ_TIMEOUT   afl -t, ms per exec (default 5000). Large TAs need"
    echo "                    more: several ~1 MB qsee_nongp TAs run ~1.8 s/exec"
    echo "                    and every seed is discarded as a timeout at 5000,"
    echo "                    so afl aborts with 'All test cases time out'."
    echo "     TAEMU_DISABLE_REDIS  turn off double-fetch recording"
    exit 0
fi


# The redis-backed recorder is what writes in/suspicious_inputs -- i.e. the
# double fetches Exploration is supposed to find. The qsee work hard-coded
# --disable-redis into every emulate invocation below, which silently switched
# detection off for every TEE (E1/E3 of the artifact then report 0 double
# fetches). Keep it opt-in via TAEMU_DISABLE_REDIS=1.
redis_arg=()
[ -n "${TAEMU_DISABLE_REDIS:-}" ] && redis_arg=(--disable-redis)

if [ ! -f /.dockerenv ]; then
    echo "Not running inside emulator Docker. Execute ./run-docker.sh first."
    exit 1
fi


cd /srv/emulator

target_path="$1"
shift

replay_seed=""
replay_args=()
if [ "$#" -gt 0 ] && [[ "$1" != -* ]]; then
    replay_seed="$1"
    shift
    replay_args=("$@")
else
    OPTS=$(getopt -o l:s:I: --long log_file:,out_suffix:,triage_hook:,in_dir:,out_dir:,triage_report_dir: -n 'fuzz.sh' -- "$@")
    eval set -- "$OPTS"

    while true; do
      case "$1" in
        -l|--log_file ) log_file="$2"; shift 2 ;;
        -s|--out_suffix ) out_suffix="$2"; shift 2 ;;
        -I|--triage_hook ) triage_hook="$2"; shift 2 ;;
        --in_dir ) in_dir="$2"; shift 2 ;;
        --out_dir ) out_dir="$2"; shift 2 ;;
        --triage_report_dir ) triage_report_dir="$2"; shift 2 ;;
        -- ) shift; break ;;
        * ) break ;;
      esac
    done
fi

out_suffix=${out_suffix:-}
triage_hook=${triage_hook:-}
triage_report_dir=${triage_report_dir:-}

quote_cmd() {
    printf '%q ' "$@"
}

generate_default_corpus() {
    if [ ! -e "$fuzz_in/foo" ]; then
        echo "foo" > "$fuzz_in/foo"
        head -c 1 /dev/zero > "$fuzz_in/foo2"
        head -c 2 /dev/zero > "$fuzz_in/foo3"
        head -c 4 /dev/zero > "$fuzz_in/foo4"
        head -c 8 /dev/zero > "$fuzz_in/foo5"
    fi
}

generate_cmd_corpus() {
    local num_cmds_file="$in_path/num_cmds.txt"
    local num_cmds
    local i

    if [ ! -f "$num_cmds_file" ]; then
        generate_default_corpus
        return
    fi

    read -r num_cmds < "$num_cmds_file"
    num_cmds="${num_cmds//[[:space:]]/}"

    if [[ ! "$num_cmds" =~ ^[0-9]+$ ]]; then
        echo "Invalid command count in $num_cmds_file; using default corpus"
        generate_default_corpus
        return
    fi

    if [ "$num_cmds" -gt 255 ]; then
        echo "Command count in $num_cmds_file exceeds one-byte range; using default corpus"
        generate_default_corpus
        return
    fi

    for i in $(seq 0 "$num_cmds"); do
        {
            printf '%b' "\\$(printf '%03o' "$i")"
            head -c 8 /dev/zero
        } > "$fuzz_in/cmd_$i"
    done
}

log_arg=()
if [ -n "${log_file:-}" ]; then
    log_arg=(--log_file "$log_file")
fi

in_path=`realpath "$target_path"`

if [ -d "$in_path" ]; then
    harness="$in_path/harness.py"
    ta=$(ls -1 "$in_path"/*.ta "$in_path"/*.elf 2>/dev/null | head -n 1)

    fuzz_in="${in_dir:-$in_path/in}"
    fuzz_out="${out_dir:-$in_path/out${out_suffix}}"

    if [ -z "$ta" ]; then
        echo "Could not find TA in $in_path"
        exit
    fi
else
    ta="$in_path"
    fuzz_in="${in_dir:-/tmp/in}"
    fuzz_out="${out_dir:-/tmp/out${out_suffix}}"
fi

echo ""Using TA: $ta
echo "Using harness: $harness"
echo "Using fuzz input dir: $fuzz_in"
echo "Using fuzz output dir: $fuzz_out"
echo "Using new-crash hook: ${triage_hook:-<none>}"
echo "Using triage report dir: ${triage_report_dir:-<default>}"

mkdir -p "$fuzz_in"
mkdir -p "$fuzz_out"
chmod -R 777 "$fuzz_in"
chmod -R 777 "$fuzz_out"

ta_name="${ta%.*}"
cp -u "$ta" rootfs/

v1a="${ta%.*}.yml"
v1b="${ta%.*}.json"

cp -u "$v1a" "rootfs/" || cp -u "$v1b" "rootfs/" || { echo "File $v1a or $v1b not found" && exit 1; }

# afl-fuzz creates its own output tree (out/default/...) mode 0700 while it
# runs, so the pre-run chmod cannot reach it. Relax it on the way out: the
# container is root and the repo is a host bind mount, so otherwise the host
# user cannot read the crashes it just produced.
relax_out_perms() {
    [ -n "${fuzz_out:-}" ] && [ -d "$fuzz_out" ] && chmod -R a+rwX "$fuzz_out" 2>/dev/null
    return 0
}
trap relax_out_perms EXIT

if [ -z "$replay_seed" ]; then
    echo "Starting fuzzing..."
    # no seed specified -> fuzz
    mkdir -p "$fuzz_out"

    if [ ! -e "$fuzz_in" ]; then
        mkdir "$fuzz_in"
    fi

    generate_cmd_corpus

    if [ ! -e "$fuzz_out" ]; then
        mkdir "$fuzz_out"
    fi
    # afl -t, in ms. 5 s is plenty for most TAs but not for the largest
    # qsee_nongp ones (~1 MB), which need FUZZ_TIMEOUT raised or afl discards
    # every seed as a timeout -- see the usage text above.
    [[ -z "$FUZZ_TIMEOUT" ]] && FUZZ_TIMEOUT=5000
    [[ -z "${FUZZTIME_GRACE:-}" ]] && FUZZTIME_GRACE=60

    info_arg=()
    if [ -n "$triage_hook" ]; then
        if [ -n "$triage_report_dir" ]; then
            info_arg=(-I "$(quote_cmd "$triage_hook" "$in_path" "$fuzz_out" "$triage_report_dir")")
        else
            info_arg=(-I "$(quote_cmd "$triage_hook" "$in_path" "$fuzz_out")")
        fi
    fi

    if [ -n "${FUZZTIME:-}" ]; then
        outer_fuzztime=$((FUZZTIME + FUZZTIME_GRACE))
        timeout -k "$FUZZTIME_GRACE" "$outer_fuzztime" \
            afl-fuzz -V "$FUZZTIME" -t "$FUZZ_TIMEOUT" -i "$fuzz_in" -o "$fuzz_out" -m none -U "${info_arg[@]}" -- \
            python3 -m emulate --use-cache "${redis_arg[@]}" --fuzz @@ --fuzz_harness "$harness" "rootfs/$(basename "$ta")" "${log_arg[@]}"
    else
        afl-fuzz -t "$FUZZ_TIMEOUT" -i "$fuzz_in" -o "$fuzz_out" -m none -U "${info_arg[@]}" -- \
            python3 -m emulate --use-cache "${redis_arg[@]}" --fuzz @@ --fuzz_harness "$harness" "rootfs/$(basename "$ta")" "${log_arg[@]}"
    fi
else 
    echo "Replaying seed $replay_seed ..."
    if [ -d "$in_path" ]; then
        # swap these when you want to attach gdb to triage
        #python3 -m emulate "${replay_args[@]}" --gdb --fuzz_replay "$replay_seed" --fuzz_harness "$harness" "rootfs/$(basename "$ta")"
        python3 -m emulate "${replay_args[@]}" --use-cache "${redis_arg[@]}" --fuzz_replay "$replay_seed" --fuzz_harness "$harness" "rootfs/$(basename "$ta")"
    else
        python3 -m emulate "${replay_args[@]}" --use-cache "${redis_arg[@]}" --fuzz_replay "$replay_seed" "rootfs/$(basename "$ta")"
    fi
fi
