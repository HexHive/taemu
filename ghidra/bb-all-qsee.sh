#!/bin/bash
set -e
for file in "../qsee_nongp/tas"/*.elf; do
  # Check if any files matched.
  [ -e "$file" ] || continue

  base="$(basename "$file")"
  stem="${base%.elf}"

  # Only process canonical TA names like "name.elf".
  # Skip patched/versioned variants such as "*.nopauth.*.elf" or "*.1.elf".
  case "$base" in
  *.nopauth.*.elf | *.*.elf)
    echo "Skipping non-canonical TA: $file"
    continue
    ;;
  esac

  # ymlfile="${file%.elf}.yml"
  # [ -e "$ymlfile" ] || { echo "YML file not found for $file"; continue; }

  # Check the file is below 1.2 MB.
  size=$(stat -c%s "$file")
  [ "$size" -lt 2200000 ] || {
    echo "File is too large: $file"
    continue
  }

  GHIDRA_MAXMEM=8G GHIDRA_MAX_CPU=10 \
    make -f direct.mk qsee-nongp-one TARGET="$file" --debug=v
done
