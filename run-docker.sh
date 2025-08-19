#!/bin/sh

docker run --rm --name emu -it -v .:/srv -w /srv/emulator ta_emu bash

# python3 -m emulate ../beanpod/
