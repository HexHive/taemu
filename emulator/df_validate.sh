#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_FORKSRV_INIT_TMOUT=99999
export AFL_NO_FASTRESUME=1
export AFL_AUTORESUME=1



if [ -z "$1" ]; then 
    echo "usage: fuzzing ./df_validate.sh <path to ta|harness folder> <path to fuzzer seed that triggered the df> <reg_hash of the df entry in .meta> <path to df_fuzzing crash> [--log_file <file>]"
    exit 0
fi


if [ ! -f /.dockerenv ]; then
    echo "Not running inside the emulator container. Run this through ae/ae.sh"
    echo "(e.g. ./ae.sh shell), which mounts the repository at /srv."
    exit 1 
fi


cd /srv/emulator

harness_path=`realpath $1`
df_seed_path=`realpath $2`
df_reg_hash=$3

harness="$harness_path/harness.py"
ta=$(ls -1 "$harness_path"/*.ta 2>/dev/null | head -n 1)
if [ -z "$ta" ]; then
    echo "Could not find TA in $in_path"
    exit
fi
ta_name="${ta::-3}"
cp -n "$ta" rootfs/
cp -n "${ta_name}.json" rootfs/
df_seed=$(basename "$df_seed_path")


echo ""Using TA: $ta
echo "Using harness: $harness"
echo "Using fuzz input dir: $fuzz_in"
echo "Using fuzz output dir: $fuzz_out"

fuzz_in="${fuzz_in}_${df_reg_hash}"
fuzz_out="${fuzz_out}_${df_reg_hash}"

if [ ! -z "$4" ]; then
    echo "Replaying seed $4 ..."
    echo -m emulate $5 --df_validate "$4" --fuzz_harness $harness --df_seed $df_seed_path --df_reg_hash $df_reg_hash $"rootfs/$(basename "$ta")" $log_arg  
    python3 -m emulate $5 --df_validate "$4" --fuzz_harness $harness --df_seed $df_seed_path --df_reg_hash $df_reg_hash $"rootfs/$(basename "$ta")" $log_arg  
fi
