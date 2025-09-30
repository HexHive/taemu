#!/bin/bash

#rm rootfs/*ta
#rm rootfs/*json
v0="$1"
v1="${v0::-3}" 
cp "$v0" rootfs/
cp "${v1}.json" rootfs/

python3 -m emulate "rootfs/$(basename "$v0")"
