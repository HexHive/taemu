#!/bin/bash

dirs=(
    "../teegris/tas"
    "../beanpod/tas"
    "../mitee/tas"
    "../qsee/tas"
)

for dir in "${dirs[@]}"; do
    tee_name=$(basename "$(dirname "$dir")") 
    for file in "$dir"/*.ta; do
        # Check if any files matched
        [ -e "$file" ] || continue
        basefile=$(basename "$file")
        jsonfile="${file%.ta}.json"               
        if [ -f "$jsonfile" ]; then
            make bbs TARGET="$basefile" TEE="$tee_name"
        fi
    done
done

