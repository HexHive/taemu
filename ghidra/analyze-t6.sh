#!/bin/bash

for file in "../t6/tas"/*.ta; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make t6 TARGET="$basefile"
done


