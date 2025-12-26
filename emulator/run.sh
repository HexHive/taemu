#!/bin/bash

v0="$1"
v1="${v0::-3}" 
cp "$v0" rootfs/
cp "${v1}.json" rootfs/


python3 -m emulate $2 "rootfs/$(basename "$v0")"
