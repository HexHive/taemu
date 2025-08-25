#!/bin/bash

for file in "../mitee/tas"/*.ta; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make mitee TARGET="$basefile"
done


