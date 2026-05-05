#!/bin/bash

DIR=$(dirname "$0")
v0="$1"
[ -z "$v0" ] && echo "Usage: $0 <path to ta>" && exit 1
v1="${v0::-3}.json"

[ ! -f "$v0" ] && echo "File $v0 not found" && exit 1
[ ! -f "${v1}" ] && echo "File $v1 not found" && exit 1

cp "$v0" "$v1" "$DIR/rootfs/"

cd "$DIR" && python3 -m emulate "rootfs/$(basename "$v0")" -g
