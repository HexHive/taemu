#!/bin/bash

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
    exit 0
fi


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

if [ -z "$replay_seed" ]; then
    echo "Starting fuzzing..."
    # no seed specified -> fuzz
    mkdir -p "$fuzz_out"

    if [ ! -e "$fuzz_in" ]; then
        mkdir "$fuzz_in"
    fi

    if [ ! -e "$fuzz_in/foo" ]; then
        echo "foo" > "$fuzz_in/foo"
        head -c 1 /dev/zero > "$fuzz_in/foo2"
        head -c 2 /dev/zero > "$fuzz_in/foo3"
        head -c 4 /dev/zero > "$fuzz_in/foo4"
        head -c 8 /dev/zero > "$fuzz_in/foo5"
    fi

    if [ ! -e "$fuzz_out" ]; then
        mkdir "$fuzz_out"
    fi
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
            python3 -m emulate --use-cache --disable-redis --fuzz @@ --fuzz_harness "$harness" "rootfs/$(basename "$ta")" "${log_arg[@]}"
    else
        afl-fuzz -t "$FUZZ_TIMEOUT" -i "$fuzz_in" -o "$fuzz_out" -m none -U "${info_arg[@]}" -- \
            python3 -m emulate --use-cache --disable-redis --fuzz @@ --fuzz_harness "$harness" "rootfs/$(basename "$ta")" "${log_arg[@]}"
    fi
else 
    echo "Replaying seed $replay_seed ..."
    if [ -d "$in_path" ]; then
        # swap these when you want to attach gdb to triage
        #python3 -m emulate "${replay_args[@]}" --gdb --fuzz_replay "$replay_seed" --fuzz_harness "$harness" "rootfs/$(basename "$ta")"
        python3 -m emulate "${replay_args[@]}" --use-cache --disable-redis --fuzz_replay "$replay_seed" --fuzz_harness "$harness" "rootfs/$(basename "$ta")"
    else
        python3 -m emulate "${replay_args[@]}" --use-cache --disable-redis --fuzz_replay "$replay_seed" "rootfs/$(basename "$ta")"
    fi
fi
