#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_FORKSRV_INIT_TMOUT=179999
export AFL_NO_FASTRESUME=1
export AFL_AUTORESUME=1
export AFL_NO_AFFINITY=1



if [ -z "$1" ]; then 
    echo "usage: fuzzing ./df_fuzz.sh <path to ta|harness folder> <path to fuzzer seed that triggered the df> <reg_hash of the df entry in .meta> [--log_file <file>]"
    exit 0
fi


if [ ! -f /.dockerenv ]; then
    echo "Not running inside the emulator container. Run this through ae/ae.sh"
    echo "(e.g. ./ae.sh shell), which mounts the repository at /srv."
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

harness_path=`realpath $1`
df_seed_path=`realpath $2`
df_reg_hash=$3

harness="$harness_path/harness.py"
ta=$(ls -1 "$harness_path"/*.ta 2>/dev/null | head -n 1)
if [ -z "$ta" ]; then
    echo "Could not find TA in $in_path"
    exit
fi
df_seed=$(basename "$df_seed_path")


echo ""Using TA: $ta
echo "Using harness: $harness"
echo "Using fuzz input dir: $fuzz_in"
echo "Using fuzz output dir: $fuzz_out"

fuzz_in="${fuzz_in}_${df_reg_hash}"
fuzz_out="${fuzz_out}_${df_reg_hash}"
ta_name="${ta::-3}"
cp -n "$ta" rootfs/
cp -n "${ta_name}.json" rootfs/

if [ -z "$4" ]; then

    echo "starting fuzzing"

    fuzz_dir="$harness_path/df_fuzz/${df_seed}_${df_reg_hash}"
    mkdir -p $fuzz_dir
    fuzz_in="$fuzz_dir/in"
    fuzz_out="$fuzz_dir/out"

    echo "Starting fuzzing..."
    # no seed specified -> fuzz
    mkdir -p $fuzz_out

    if [ ! -e "$fuzz_in" ]; then
        mkdir $fuzz_in
        echo "foo" > "$fuzz_in/foo"
        head -c 1 /dev/zero > "$fuzz_in/foo2"
        head -c 2 /dev/zero > "$fuzz_in/foo3"
        head -c 4 /dev/zero > "$fuzz_in/foo4"
        head -c 8 /dev/zero > "$fuzz_in/foo5"
    fi

    if [ ! -e "$fuzz_out" ]; then
        mkdir $fuzz_out
    fi

    chmod -R 777 "$fuzz_in"
    chmod -R 777 "$fuzz_out"
    
    if [ -z "${FUZZTIME}" ]; then
            afl-fuzz -t 5000 -i $fuzz_in -o $fuzz_out -m none -U -- python3 -m emulate --df_fuzz @@ --fuzz_harness $harness --df_seed $df_seed_path --df_reg_hash $df_reg_hash "rootfs/$(basename "$ta")" $log_arg
    else
            timeout -k $FUZZTIME $FUZZTIME afl-fuzz -V $FUZZTIME -t 5000 -i $fuzz_in -o $fuzz_out -m none -U -- python3 -m emulate --df_fuzz @@ --fuzz_harness $harness --df_seed $df_seed_path --df_reg_hash $df_reg_hash "rootfs/$(basename "$ta")" $log_arg
    fi
else
    echo "Replaying seed $4 ..."
    python3 -m emulate -v -d --df_replay "$4" --fuzz_harness $harness --df_seed $df_seed_path --df_reg_hash $df_reg_hash $"rootfs/$(basename "$ta")" $log_arg  
fi
