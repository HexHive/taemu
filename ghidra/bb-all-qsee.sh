#!/bin/bash

for file in "../qsee_nongp/tas"/*.elf; do
    # Check if any files matched
    [ -e "$file" ] || continue
    ymlfile="${file%.elf}.yml"
    [ -e $ymlfile ] || { echo "YML file not found for $file"; continue; }

    # Check the file is below 800KB
    size=$(stat -c%s "$file")
    [ $size -lt 1200000 ] || { echo "File is too large: $file"; continue; }

    GHIDRA_MAXMEM=8G GHIDRA_MAX_CPU=1 make bbs-qsee_nongp TARGET=$file 2>&1 >>"bbs-qsee_nongp-$(basename $file).log"
done