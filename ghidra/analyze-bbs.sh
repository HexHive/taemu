#!/bin/bash

dirs=(
    "../t6/tas"
    "../teegris/tas"
    "../beanpod/tas"
    "../mitee/tas"
)

for dir in "${dirs[@]}"; do
    for file in "$dir"/*.ta; do
        # Check if any files matched
        [ -e "$file" ] || continue
        basefile=$(basename "$file")
        jsonfile="${file%.ta}.json"               
        if [ -f "$jsonfile" ]; then
            make bbs TARGET="$basefile" TEE=b6
        fi
    done
done

