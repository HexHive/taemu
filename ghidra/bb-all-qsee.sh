#!/bin/bash
set -e

ta_base_dir="../qsee_nongp/tas"
if [ $# -gt 0 ]; then
  files=("$@")
else
  files=("${ta_base_dir}"/*.elf)
fi

#target files are in shape of ../qsee_nongp/tas/bbs/bb_<name>.elf.json
target_files=()

for file in "${files[@]}"; do
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
  target_files+=("${ta_base_dir}/bbs/bb_${stem}.elf.json")
done
make -f direct.mk own-project
GHIDRA_MAXMEM=8G GHIDRA_MAX_CPU=10 \
  make -f direct.mk \
    ${target_files[@]} \
    --debug=v
