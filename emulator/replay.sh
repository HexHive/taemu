#!/bin/bash

base_dir="$1"

rm "$base_dir"/out/cov/*

for file in "$base_dir"/out/*/queue/*; do
    [[ -e "$file" ]] || continue
    ./fuzz.sh $base_dir "$file"
done

rm "$base_dir"/drcov.log
/opt/afl/drcov-merge "$base_dir"/drcov.log "$base_dir"/out/cov/*
