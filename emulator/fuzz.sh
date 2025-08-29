#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1

rm rootfs/*ta
rm rootfs/*json

v0="$1"
v1="${v0::-3}" 
cp "$v0" rootfs/
cp "${v1}.json" rootfs/

mkdir /tmp/in
echo "foo" > /tmp/in/foo

mkdir /tmp/out
afl-fuzz -i /tmp/in -o /tmp/out -m none -U -- python3 -m emulate --fuzz @@ "rootfs/$(basename "$v0")"
