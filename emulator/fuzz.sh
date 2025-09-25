#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_FORKSRV_INIT_TMOUT=99999
export AFL_AUTORESUME=1

#rm rootfs/*ta
#rm rootfs/*json

if [ -z "$1" ]; then 
    echo "usage fuzzing ./fuzz.sh <path to ta>"
    echo "usage replay seed ./fuzz.sh <path to ta> <path to seed> "
    echo "usage fuzzing ./fuzz.sh <path to harness folder>"
    echo "usage replay seed ./fuzz.sh <path to harness folder> <path to seed> "
    exit 0
fi

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

    if [ ! -e "$fuzz_out" ]; then
        mkdir $fuzz_out
    fi

    if [ -d "$in_path" ]; then
        afl-fuzz -c 0 -t 2000 -i $fuzz_in -o $fuzz_out -m none -U -- python3 -m emulate --fuzz @@ --fuzz_harness $harness "rootfs/$(basename "$ta")"
    else 
        afl-fuzz -c 0 -t 2000 -i $fuzz_in -o $fuzz_out -m none -U -- python3 -m emulate --fuzz @@ "rootfs/$(basename "$ta")"
    fi
else 
    if [ -d "$in_path" ]; then
        # swap these when you want to attach gdb to triage
        #python3 -m emulate $3 --gdb --fuzz_replay $2 --fuzz_harness $harness "rootfs/$(basename "$ta")"
        python3 -m emulate $3 --fuzz_replay $2 --fuzz_harness $harness "rootfs/$(basename "$ta")"
    else
        python3 -m emulate $3 --fuzz_replay $2 "rootfs/$(basename "$v0")"
    fi
fi
