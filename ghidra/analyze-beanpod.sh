#!/bin/bash

for file in "../beanpod/tas"/*.ta; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make beanpod TARGET="$basefile"
done


