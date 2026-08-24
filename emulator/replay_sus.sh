#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_FORKSRV_INIT_TMOUT=199999
export AFL_NO_FASTRESUME=1
export AFL_AUTORESUME=1



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
    ta="$in_path"
    fuzz_in="/tmp/in"
    fuzz_out="tmp/out"
fi

echo ""Using TA: $ta
echo "Using harness: $harness"
echo "Using fuzz input dir: $fuzz_in"
echo "Using fuzz output dir: $fuzz_out"

chmod -R 777 "$fuzz_in"
chmod -R 777 "$fuzz_out"

ta_name="${ta::-3}"
cp -u "$ta" rootfs/
cp -u "${ta_name}.json" rootfs/

if [ ! -z "$2" ]; then
    echo "Replaying seed $2 ..."
    python3 -m emulate $3 --sus_in_replay --fuzz_replay $2 --fuzz_harness $harness "rootfs/$(basename "$ta")"
fi
