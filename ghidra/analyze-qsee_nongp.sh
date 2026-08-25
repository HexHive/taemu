#!/bin/bash

for file in "../qsee_nongp/tas"/*.elf; do
    # Check if any files matched
    [ -e "$file" ] || continue
    # Check there is no "patched", "nopauth", or "template" in the filename
    if [[ "$file" == *"patched"* || "$file" == *"nopauth"* || "$file" == *"template"* ]]; then
        echo "Skipping $file because it contains 'patched', 'nopauth', or 'template'"
        continue
    fi
	basefile=$(basename "$file")
    make qsee_nongp TARGET="$basefile"
done
