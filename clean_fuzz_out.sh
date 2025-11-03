#!/bin/bash

if [ -z "$1" ]; then
	exit -1
fi
find . -type d -name "$1" -exec rm -rf {} +
