#!/bin/bash

for file in "../../tas"/*.ta; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make run TARGET="$basefile"
done


