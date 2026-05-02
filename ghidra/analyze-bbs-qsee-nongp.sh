#!/bin/bash

dirs=(
  "../qsee_nongp/tas/"
)

for dir in "${dirs[@]}"; do
  tee_name=$(basename "$(dirname "$dir")")
  for file in "$dir"/*.elf; do
    # Check if any files matched
    [ -e "$file" ] || continue
    basefile=$(basename "$file")
    ymlfile="${file%.elf}.yml"
    jsonfile="${file%.elf}.json"
    if [ -f "$ymlfile" ] || [ -f "$jsonfile" ]; then
      make bbs-qsee_nongp TARGET="$basefile" TEE="$tee_name"
    fi
  done
done
