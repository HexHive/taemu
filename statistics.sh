#!/bin/bash
root_dir="$(pwd -P)"

# when using --help
if [[ $# -eq 1 && $1 == "--help" ]]; then
  echo "Usage: $0 [--detail] [--ss_rdir <ss_rdir>]"
  exit 1
fi

detail=false
SS_RDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --detail)
      detail=1
      shift
      ;;
    --ss_rdir)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ss_rdir requires a value"
        usage
        exit 1
      fi
      SS_RDIR="$2"
      shift 2
      ;;
    *)
      echo "Error: unexpected argument: $1"
      usage
      exit 1
      ;;
  esac
done


# Count items under path with optional filters.
# Usage:
#   count_filtered <path> [--type f|d] [--name <glob>] [--regex <regex>] [--exclude <path-glob>] [--norecurse]
# Examples:
#   count_filtered "/path/to/dir" --type d
#   count_filtered "." --type f --name "*.sh" --norecurse
#   count_filtered "." --type f --regex ".*\\.(sh|py)$"
#   count_filtered "." --type f --exclude "*/node_modules/*"
#   count_filtered "." --type f --name "*.txt" --exclude "*/temp/*" --norecurse
count_filtered() {
  local path="$1"
  shift
  local find_type=""
  local find_name=""
  local find_regex=""
  local find_exclude=()
  local maxdepth=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --type)
        find_type="$2"
        shift 2
        ;;
      --name)
        find_name="$2"
        shift 2
        ;;
      --regex)
        find_regex="$2"
        shift 2
        ;;
      --exclude)
        find_exclude+=(-not -path "$2")
        shift 2
        ;;
      --norecurse)
        maxdepth="-maxdepth 1"
        shift
        ;;
      *)
        shift
        ;;
    esac
  done

  [[ ! -e "$path" ]] && echo 0 && return 0

  local find_args=("$path")
  [[ -n "$maxdepth" ]] && find_args+=($maxdepth)
  [[ "$find_type" == "f" ]] && find_args+=(-type f)
  [[ "$find_type" == "d" ]] && find_args+=(-type d)
  [[ -n "$find_name" ]] && find_args+=(-name "$find_name")
  [[ -n "$find_regex" ]] && find_args+=(-regex "$find_regex")
  find_args+=("${find_exclude[@]}")
  find_args+=(-print)

  find "${find_args[@]}" 2>/dev/null | wc -l
}


TEEs=(
  "$root_dir/mitee"
  "$root_dir/beanpod"
  "$root_dir/teegris"
  "$root_dir/qsee"
)

# Terminal color
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color


echo -e "[+] ${RED}TA with double fetches${NC}"
for TEE in "${TEEs[@]}"; do
  TEE_HARNESS_DIR="$TEE/harness"
  ta_double_fetchs=0
  ta_list=()
  if [[ ! -d "$TEE_HARNESS_DIR" ]]; then
    continue
  fi
  for TA in "$TEE_HARNESS_DIR"/*; do
    if [[ -d "$TA" ]]; then
      cnt=$(count_filtered "$TA" --type f --name "*.meta")
      if [[ $cnt -gt 0 ]]; then
        if [[ $detail == true ]]; then
          echo -e "[DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}TA${NC}: $TA, ${BLUE}Double Fetch Count${NC}: $cnt"
        fi
        ta_list+=("$TA")
        ta_double_fetchs=$((ta_double_fetchs + 1))
      fi
    fi
  done
  echo -e "[!!][DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}TA with double_fetches${NC}: $ta_double_fetchs, ${BLUE}TA List${NC}: ${ta_list[@]}"
done

echo -e "[+] ${RED}Double fetches${NC}"
#TODO
echo "@TODO@"

echo -e "[+] ${RED}Deduplicated double fetches${NC}"
for TEE in "${TEEs[@]}"; do
  TEE_HARNESS_DIR="$TEE/harness"
  deduplicated_double_fetches=0
  if [[ ! -d "$TEE_HARNESS_DIR" ]]; then
    continue
  fi
  for TA in "$TEE_HARNESS_DIR"/*; do
    deduplicated_double_fetches_ta=0
    if [[ -d "$TA" ]]; then
      meta_list=()
      while IFS= read -r -d '' f; do
        meta_list+=("$f")
      done < <(find "$TA/in/suspicious_inputs_replay" -type f -name "*.meta" -print0 2>/dev/null)
      for f in "${meta_list[@]}"; do
        deduplicated_double_fetches_ta=$((deduplicated_double_fetches_ta+$(jq '[.records[] | select(.regs.is_read == true and .is_second_fetch == true)] | length' "$f")))
      done
    fi
    deduplicated_double_fetches=$((deduplicated_double_fetches+deduplicated_double_fetches_ta))
    if [[ $detail == true ]]; then
      echo -e "[DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}TA${NC}: $TA, ${BLUE}Deduplicated double_fetches${NC}: $deduplicated_double_fetches_ta"
    fi
  done
  echo -e "[!!][DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}Deduplicated double_fetches${NC}: $deduplicated_double_fetches"
done



echo -e "[+] ${RED}Merged double fetches${NC}"
for TEE in "${TEEs[@]}"; do
  TEE_HARNESS_DIR="$TEE/harness/"
  tee_merged_df_cnt=0
  if [[ ! -d "$TEE_HARNESS_DIR" ]]; then
    continue
  fi
  for TA in "$TEE_HARNESS_DIR"/*; do
    TA_DF_DIR="$TA/df_fuzz/"
    if [[ ! -d "$TA_DF_DIR" ]]; then
      continue
    fi
    merged_df_list=()
    merged_df_count=0
    for DF_SNAPSHOT in "$TA_DF_DIR"/*; do
      if [[ -d "$DF_SNAPSHOT" ]]; then
          merged_df_list+=("$DF_SNAPSHOT")
          merged_df_count=$((merged_df_count + 1))
      fi
    done
    tee_merged_df_cnt=$((tee_merged_df_cnt+merged_df_count))
    if [[ $detail == true ]]; then
      echo -e "[DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}TA${NC}: $TA, ${BLUE}Merged DF List${NC}: ${merged_df_list[@]}, ${MAGENTA}Merged DF Count${NC}: $merged_df_count"
    fi
  done
  echo -e "[!!][DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}Merged DF Count${NC}: $tee_merged_df_cnt"
done


echo -e "[+] ${RED}Crashes${NC}"
for TEE in "${TEEs[@]}"; do
  TEE_HARNESS_DIR="$TEE/harness/"
  tee_crashes_cnt=0
  tee_crashes_df_cnt=0
  if [[ ! -d "$TEE_HARNESS_DIR" ]]; then
    continue
  fi
  for TA in "$TEE_HARNESS_DIR"/*; do
    TA_DF_DIR="$TA/df_fuzz/"
    if [[ ! -d "$TA_DF_DIR" ]]; then
      continue
    fi
    ta_crashes_list=()
    ta_crashes_cnt=0
    ta_crashes_df_cnt=0
    for DF_SNAPSHOT in "$TA_DF_DIR"/*; do
      CRASHES_DIR="$DF_SNAPSHOT/out/default/crashes"
      if [[ -d "$CRASHES_DIR" ]]; then
        cnt=$(count_filtered "$CRASHES_DIR" --type f --name "id:*" --exclude "*/*.df")
        cntdf=$(count_filtered "$CRASHES_DIR" --type f --name "id:*.df")
        ta_crashes_list+=("$CRASHES_DIR")
        ta_crashes_cnt=$((ta_crashes_cnt+cnt))
        ta_crashes_df_cnt=$((ta_crashes_df_cnt+cntdf))
      fi
    done
    tee_crashes_cnt=$((tee_crashes_cnt+ta_crashes_cnt))
    tee_crashes_df_cnt=$((tee_crashes_df_cnt+ta_crashes_df_cnt))
    if [[ $detail == true ]]; then
      echo -e "[DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}TA${NC}: $TA, ${BLUE}Crashes List${NC}: ${ta_crashes_list[@]}, ${MAGENTA}Crashes Count${NC}: $ta_crashes_cnt"
    fi
  done
  echo -e "[!!][DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}Crashes Count${NC}: $tee_crashes_cnt"
  echo -e "[!!][DATA] ${YELLOW}TEE${NC}: $TEE, ${GREEN}DF Crashes Count${NC}: $tee_crashes_df_cnt"
done