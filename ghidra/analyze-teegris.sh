#!/bin/bash

for file in "../teegris/tas"/*.ta; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make teegris TARGET="$basefile"
done


