#!/bin/bash

for file in "../optee/tas"/*.ta; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make optee TARGET="$basefile"
done


