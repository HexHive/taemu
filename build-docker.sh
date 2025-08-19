#!/bin/sh 

if [ ! -f "./flag1.txt" ]; then
	echo "EPFL{part1flag..." > flag1.txt
fi
docker build . -t ta_emu
