#!/bin/sh

docker run --rm --name emu --network host -it -v .:/srv -w /srv/emulator -v /dev/shm:/dev/shm --shm-size=10g ta_emu bash

# python3 -m emulate ../beanpod/
