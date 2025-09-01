#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1

rm rootfs/*ta
rm rootfs/*json

if [ -z "$1" ]; then 
    echo "usage fuzzing ./fuzz.sh <path to ta>"
    echo "usage replay seed ./fuzz.sh <path to ta> <path to seed> "
    echo "usage fuzzing ./fuzz.sh <path to harness folder>"
    echo "usage replay seed ./fuzz.sh <path to harness folder> <path to seed> "
    exit 0
fi

if [ -d "$1" ]; then 
    harness="$1/harness.py"
    ta=$(ls -1 "$1"/*.ta 2>/dev/null | head -n 1)
    fuzz_in="$1/in"
    fuzz_out="$1/out_$(date +%s)"
else
    ta="$1"
    fuzz_in="/tmp/in"
    fuzz_out="tmp/out"
fi

ta_name="${ta::-3}" 
cp "$ta" rootfs/
cp "${ta_name}.json" rootfs/

if [ -z "$2" ]; then
    # no seed specified -> fuzz
    mkdir -p $fuzz_out

    if [ ! -e "$fuzz_in" ]; then
        mkdir $fuzz_in
        echo "foo" > "$fuzz_in/foo"
    fi 

    if [ -d "$1" ]; then
        afl-fuzz -i $fuzz_in -o $fuzz_out -m none -U -- python3 -m emulate --fuzz @@ --fuzz_harness $harness "rootfs/$(basename "$ta")"
    else 
        afl-fuzz -i $fuzz_in -o $fuzz_out -m none -U -- python3 -m emulate --fuzz @@ "rootfs/$(basename "$ta")"
    fi
else 
    if [ -d "$1" ]; then
        python3 -m emulate $3 --fuzz_replay $2 --fuzz_harness $harness "rootfs/$(basename "$ta")"
    else
        python3 -m emulate $3 --fuzz_replay $2 "rootfs/$(basename "$v0")"
    fi
fi
