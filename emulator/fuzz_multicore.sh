#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_FORKSRV_INIT_TMOUT=1999999
export AFL_NO_FASTRESUME=1
export AFL_AUTORESUME=1
export AFL_NO_AFFINITY=1


if [ -z "$1" ]; then 
    echo "usage: fuzzing ./fuzz.sh <path to ta|harness folder> [--log_file <file>]"
    echo "usage: replay seed ./fuzz.sh <path to ta|harness folder> <path to seed>"
    exit 0
fi


if [ ! -f /.dockerenv ]; then
    echo "Not running inside emulator Docker. Execute ./run-docker.sh first."
    exit 1
fi


cd /srv/emulator

OPTS=$(getopt -o l: --long log_file: -n 'fuzz.sh' -- "$@")
eval set -- "$OPTS"

while true; do
  case "$1" in
    -l|--log_file ) log_file="$2"; shift 2 ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

log_arg=${log_file:+--log_file "$log_file"}

in_path=`realpath $1`

if [ -d "$in_path" ]; then
    harness="$in_path/harness.py"
    ta=$(ls -1 "$in_path"/*.ta 2>/dev/null | head -n 1)

    fuzz_in="$in_path/in"
    fuzz_out="$in_path/out"

    if [ -z "$ta" ]; then
        echo "Could not find TA in $in_path"
        exit
    fi
else
    echo "specify harenss"
    exit -1
fi

echo ""Using TA: $ta
echo "Using harness: $harness"
echo "Using fuzz input dir: $fuzz_in"
echo "Using fuzz output dir: $fuzz_out"

chmod -R 777 "$fuzz_in"
chmod -R 777 "$fuzz_out"

ta_name="${ta::-3}"
cp "$ta" rootfs/
cp "${ta_name}.json" rootfs/

if [ -z "$2" ]; then
    echo "Starting fuzzing..."
    # no seed specified -> fuzz
    rm -rf "$in_path/record_meta/"

    mkdir -p $fuzz_out

    if [ ! -e "$fuzz_in" ]; then
        mkdir $fuzz_in
    fi

    if [ ! -e "$fuzz_in/foo" ]; then
        echo "foo" > "$fuzz_in/foo"
        head -c 1 /dev/zero > "$fuzz_in/foo2"
        head -c 2 /dev/zero > "$fuzz_in/foo3"
        head -c 4 /dev/zero > "$fuzz_in/foo4"
        head -c 8 /dev/zero > "$fuzz_in/foo5"
    fi

    if [ ! -e "$fuzz_out" ]; then
        mkdir $fuzz_out
    fi

    NUM_INSTANCES=2

    run_afl() {
        ROLE=$1
        ID=$2

        if [ -z "${FUZZTIME}" ]; then
            afl-fuzz \
                -t 5000 \
                -i "$fuzz_in" \
                -o "$fuzz_out" \
                -m none \
                -U \
                $ROLE "$ID" \
                -- python3 -m emulate \
                    --fuzz @@ \
                    --fuzz_harness "$harness" \
                    "rootfs/$(basename "$ta")" \
                    $log_arg
        else
            timeout -k "$FUZZTIME" "$FUZZTIME" afl-fuzz \
                -V "$FUZZTIME" \
                -t 5000 \
                -i "$fuzz_in" \
                -o "$fuzz_out" \
                -m none \
                -U \
                $ROLE "$ID" \
                -- python3 -m emulate \
                    --fuzz @@ \
                    --fuzz_harness "$harness" \
                    "rootfs/$(basename "$ta")" \
                    $log_arg
        fi
    }

    echo "Starting AFL with $NUM_INSTANCES parallel instances..."

    # Master
    run_afl -M fuzzer00 &

    # Slaves
    for i in $(seq 1 $((NUM_INSTANCES - 1))); do
        ID=$(printf "fuzzer%02d" "$i")
        run_afl -S "$ID" &
    done

    wait

else 
    echo "Replaying seed $2 ..."
    if [ -d "$in_path" ]; then
        # swap these when you want to attach gdb to triage
        #python3 -m emulate $3 --gdb --fuzz_replay $2 --fuzz_harness $harness "rootfs/$(basename "$ta")"
        python3 -m emulate $3 --fuzz_replay $2 --fuzz_harness $harness "rootfs/$(basename "$ta")"
    else
        python3 -m emulate $3 --fuzz_replay $2 "rootfs/$(basename "$v0")"
    fi
fi
