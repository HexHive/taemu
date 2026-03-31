#!/bin/bash

DIR=$(dirname "$0")
v0="$1"
[ -z "$v0" ] && echo "Usage: $0 <path to ta>" && exit 1
[ ! -f "$v0" ] && echo "File $v0 not found" && exit 1
cp "$v0" "$DIR/rootfs/"
shift

v1a="${v0%.*}.yml"
v1b="${v0%.*}.json"

found_one=false
if [ -f "$v1a" ]; then
    cp "$v1a" "$DIR/rootfs/"
    found_one=true
fi
if [ -f "$v1b" ]; then
    cp "$v1b" "$DIR/rootfs/"
    found_one=true
fi
if [ ! "$found_one" ]; then
    echo "File $v1a or $v1b not found" && exit 1
fi

cd "$DIR" && python3 -m emulate $@ "rootfs/$(basename "$v0")" 
