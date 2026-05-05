#!/bin/bash

base_dir="$1"
implemented_apis="$2"

export TAEMU_IMPLEMENTED_APIS="$implemented_apis"

rm "$base_dir"/out/cov/*

for file in "$base_dir"/out/*/queue/*; do
    [[ -e "$file" ]] || continue
    ./fuzz.sh $base_dir "$file"
done

rm "$base_dir"/drcov.log
/opt/afl/drcov-merge -u "$base_dir"/drcov.log "$base_dir"/out/cov/*
