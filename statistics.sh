#!/bin/bash
# Computes the numbers of Table I of the paper from the campaign data in this
# repository:
#
#   # TAs | # TAs w/o Local Copy | # TAs with Overl. Fetches |
#   # Overl. Fetches | # Overl. Fetches merged | # Crashes | # Crashes Distilled
#
# Everything is derived from the on-disk campaign state:
#   <tee>/tas/                                     the TA corpus
#   <tee>/harness/<h>/in/suspicious_inputs/        Exploration records (annotated)
#   <tee>/harness/<h>/in/suspicious_inputs_replay/ after deduplication
#   <tee>/harness/<h>/df_fuzz/<seed>_<reghash>/    one dir per merged overlapped
#                                                  fetch, i.e. one snapshot
#   .../out/default/crashes/id:*                   Fetch-Anchored Fuzzing crashes
#   .../out/default/crashes/id:*.df                crashes kept by Distillation
#
# Usage:
#   ./statistics.sh [--detail] [--json <file>] [--include campaign|ae|all]
#
# --include selects which harness directories are counted:
#   campaign  (default) the harnesses of the paper's campaign
#   ae        only the ae_* scratch harnesses of an artifact-evaluation run,
#             i.e. Table I for the campaign *you* just ran
#   all       both
#
# The repository root is taken from $TAEMU_ROOT, falling back to the directory
# of this script, so it can be run from anywhere (also from the AE container).
set -uo pipefail

root_dir="${TAEMU_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)}"

detail=false
json_out=""
include="campaign"

usage() {
  echo "Usage: $0 [--detail] [--json <file>] [--include campaign|ae|all]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --detail) detail=true; shift ;;
    --json)
      [[ $# -lt 2 ]] && { echo "Error: --json requires a value"; usage; exit 1; }
      json_out="$2"; shift 2 ;;
    --include)
      [[ $# -lt 2 ]] && { echo "Error: --include requires a value"; usage; exit 1; }
      include="$2"
      case "$include" in campaign|ae|all) ;; *) echo "Error: bad --include"; exit 1 ;; esac
      shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Error: unexpected argument: $1"; usage; exit 1 ;;
  esac
done

# TEEs of Table I. Kinibi TAs are emulated with the Beanpod runtime (Beanpod is
# a Kinibi derivative), so their harnesses live under beanpod/harness.
TEEs=(teegris qsee kinibi mitee beanpod)

kinibiTas=(
  "df1e_fuzz"
  "abcd_fuzz"
  "0801_fuzz"
)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; NC='\033[0m'

harness_dir_of() {
  local tee="$1"
  if [[ "$tee" == "kinibi" ]]; then
    echo "$root_dir/beanpod/harness"
  else
    echo "$root_dir/$tee/harness"
  fi
}

is_tee_harness() {
  # Is this harness directory part of the given TEE's TA set?
  local tee="$1" harness="$2" base
  base="$(basename "$harness")"
  # ae_* are the scratch harnesses of an artifact-evaluation run (README.md).
  # They are copies of a campaign harness, so mixing both would double-count.
  case "$include" in
    campaign) [[ "$base" == ae_* ]] && return 1 ;;
    ae)       [[ "$base" == ae_* ]] || return 1 ;;
  esac
  if [[ "$tee" == "kinibi" ]]; then
    # A working harness is named ae_e<n>_<harness>; match on the harness it was
    # copied from, otherwise no Kinibi TA is ever recognised in an AE run.
    [[ " ${kinibiTas[*]} " == *" ${base#ae_e*_} "* ]]
    return $?
  fi
  return 0
}

ta_of_harness() {
  # Unique identity of the TA a harness fuzzes: the name of its .ta file.
  # Several harnesses may target the same TA (e.g. mitee/377e_fuzz and
  # mitee/377e_double_fetch_stackov); those count as one TA.
  local harness="$1" ta
  ta="$(ls -1 "$harness"/*.ta 2>/dev/null | head -n 1)"
  [[ -z "$ta" ]] && return 1
  basename "$ta" .ta
}

count_tas_in_corpus() {
  # Size of the TA corpus of a TEE. Kinibi TAs are shipped as .tlbin/.tabin.
  local tee="$1" dir="$root_dir/$tee/tas"
  [[ -d "$dir" ]] || { echo 0; return; }
  find "$dir" -maxdepth 1 -type f \
       \( -name "*.ta" -o -name "*.tlbin" -o -name "*.tabin" \) -printf "%f\n" 2>/dev/null \
    | sed 's/\.[^.]*$//' | sort -u | wc -l
}

count_overlapped_fetches() {
  # Overlapped fetches recorded in a directory of .meta files: records that the
  # recorder/annotator marked as a second fetch of an already accessed
  # shared-memory range, and that are reads.
  local dir="$1" n
  [[ -d "$dir" ]] || { echo 0; return; }
  # xargs may need several jq invocations for large directories; sum them up.
  n=$(find "$dir" -maxdepth 1 -type f -name "*.meta" -print0 2>/dev/null \
      | xargs -0 -r jq -n '
          reduce inputs as $m (0;
            . + ([$m.records[]? | select(.is_second_fetch == true and .regs.is_read == true)] | length))' \
        2>/dev/null \
      | awk '{s += $1} END {printf "%d\n", s + 0}')
  echo "${n:-0}"
}

count_overlapped_fetches_recorded() {
  # All overlapped fetches a harness recorded, counted over both recording
  # directories. Deduplication moves a seed from suspicious_inputs to
  # suspicious_inputs_replay (and may delete the original), so a seed present in
  # both must be counted once: suspicious_inputs_replay wins.
  local harness="$1" raw="$1/in/suspicious_inputs" rep="$1/in/suspicious_inputs_replay"
  local list n
  list=$(mktemp)
  if [[ -d "$rep" ]]; then
    find "$rep" -maxdepth 1 -type f -name "*.meta" -print0 2>/dev/null >> "$list"
  fi
  if [[ -d "$raw" ]]; then
    while IFS= read -r -d "" f; do
      [[ -e "$rep/$(basename "$f")" ]] && continue
      printf "%s\0" "$f" >> "$list"
    done < <(find "$raw" -maxdepth 1 -type f -name "*.meta" -print0 2>/dev/null)
  fi
  n=$(xargs -0 -r jq -n '
        reduce inputs as $m (0;
          . + ([$m.records[]? | select(.is_second_fetch == true and .regs.is_read == true)] | length))' \
      < "$list" 2>/dev/null | awk '{s += $1} END {printf "%d\n", s + 0}')
  rm -f "$list"
  echo "${n:-0}"
}

declare -A M_TAS M_HARNESSED M_WITH_DF M_FETCHES M_FETCHES_DEDUP M_MERGED M_CRASHES M_DISTILLED
# --include ae: an artifact-evaluation campaign keeps one working directory per
# *stage* and TA (ae_e1_<ta> for Exploration, ae_e2_<ta> for Fetch-Anchored
# Fuzzing, ae_e3_<ta> for Distillation), and each stage stages a copy of what it
# consumes. Summing over those directories would count the same seeds and the
# same crashes two or three times, so per TA the maximum of each metric across
# its stage directories is taken instead.
declare -A S_FETCHES S_FETCHES_DEDUP S_MERGED S_CRASHES S_DISTILLED

for tee in "${TEEs[@]}"; do
  harness_root="$(harness_dir_of "$tee")"
  tas_with_df=(); tas_harnessed=()
  fetches=0; fetches_dedup=0; merged=0; crashes=0; distilled=0

  if [[ -d "$harness_root" ]]; then
    for harness in "$harness_root"/*; do
      [[ -d "$harness" ]] || continue
      is_tee_harness "$tee" "$harness" || continue
      ta_id="$(ta_of_harness "$harness")" || continue
      tas_harnessed+=("$ta_id")

      h_fetches=$(count_overlapped_fetches_recorded "$harness")
      h_fetches_dedup=$(count_overlapped_fetches "$harness/in/suspicious_inputs_replay")

      if [[ $h_fetches -gt 0 || $h_fetches_dedup -gt 0 ]]; then
        tas_with_df+=("$ta_id")
      fi

      h_merged=0
      if [[ -d "$harness/df_fuzz" ]]; then
        h_merged=$(find "$harness/df_fuzz" -mindepth 1 -maxdepth 1 -type d | wc -l)
      fi

      h_crashes=$(find "$harness/df_fuzz" -path "*out/default/crashes/id:*" -type f \
                    -not -name "*.output" -not -name "*.df" 2>/dev/null | wc -l)
      h_distilled=$(find "$harness/df_fuzz" -path "*out/default/crashes/id:*.df" -type f \
                    2>/dev/null | wc -l)

      if [[ "$include" == "ae" ]]; then
        # keep the per-TA maximum across the stage directories
        local_key="$tee|$ta_id"
        (( h_fetches       > ${S_FETCHES[$local_key]:-0}       )) && S_FETCHES[$local_key]=$h_fetches
        (( h_fetches_dedup > ${S_FETCHES_DEDUP[$local_key]:-0} )) && S_FETCHES_DEDUP[$local_key]=$h_fetches_dedup
        (( h_merged        > ${S_MERGED[$local_key]:-0}        )) && S_MERGED[$local_key]=$h_merged
        (( h_crashes       > ${S_CRASHES[$local_key]:-0}       )) && S_CRASHES[$local_key]=$h_crashes
        (( h_distilled     > ${S_DISTILLED[$local_key]:-0}     )) && S_DISTILLED[$local_key]=$h_distilled
      else
        fetches=$((fetches + h_fetches))
        fetches_dedup=$((fetches_dedup + h_fetches_dedup))
        merged=$((merged + h_merged))
        crashes=$((crashes + h_crashes))
        distilled=$((distilled + h_distilled))
      fi

      if [[ $detail == true ]]; then
        echo -e "[DATA] ${YELLOW}TEE${NC}: $tee, ${GREEN}harness${NC}: $(basename "$harness")," \
                "${GREEN}TA${NC}: $ta_id, ${BLUE}overl. fetches${NC}: $h_fetches," \
                "${BLUE}dedup${NC}: $h_fetches_dedup, ${MAGENTA}snapshots${NC}: $h_merged," \
                "${RED}crashes${NC}: $h_crashes, ${RED}distilled${NC}: $h_distilled"
      fi
    done
  fi

  if [[ "$include" == "ae" ]]; then
    for ta_id in $(printf '%s\n' "${tas_harnessed[@]:-}" | sed '/^$/d' | sort -u); do
      k="$tee|$ta_id"
      fetches=$((fetches + ${S_FETCHES[$k]:-0}))
      fetches_dedup=$((fetches_dedup + ${S_FETCHES_DEDUP[$k]:-0}))
      merged=$((merged + ${S_MERGED[$k]:-0}))
      crashes=$((crashes + ${S_CRASHES[$k]:-0}))
      distilled=$((distilled + ${S_DISTILLED[$k]:-0}))
    done
  fi

  uniq_harnessed=$(printf '%s\n' "${tas_harnessed[@]:-}" | sed '/^$/d' | sort -u | wc -l)
  uniq_with_df=$(printf '%s\n' "${tas_with_df[@]:-}" | sed '/^$/d' | sort -u | wc -l)

  M_TAS[$tee]=$(count_tas_in_corpus "$tee")
  M_HARNESSED[$tee]=$uniq_harnessed
  M_WITH_DF[$tee]=$uniq_with_df
  M_FETCHES[$tee]=$fetches
  M_FETCHES_DEDUP[$tee]=$fetches_dedup
  M_MERGED[$tee]=$merged
  M_CRASHES[$tee]=$crashes
  M_DISTILLED[$tee]=$distilled
done

# ------------------------------------------------------------------ reporting
printf "\n%-10s %8s %10s %10s %12s %12s %10s %10s\n" \
  "TEE" "#TAs" "#noCopy" "#w/OvlF" "#OvlFetch" "#Merged" "#Crashes" "#Distill"
printf -- "----------------------------------------------------------------------------------------\n"

t_tas=0; t_harnessed=0; t_with_df=0; t_fetches=0; t_merged=0; t_crashes=0; t_distilled=0
for tee in "${TEEs[@]}"; do
  printf "%-10s %8s %10s %10s %12s %12s %10s %10s\n" \
    "$tee" "${M_TAS[$tee]}" "${M_HARNESSED[$tee]}" "${M_WITH_DF[$tee]}" \
    "${M_FETCHES[$tee]}" "${M_MERGED[$tee]}" "${M_CRASHES[$tee]}" "${M_DISTILLED[$tee]}"
  t_tas=$((t_tas + M_TAS[$tee]));             t_harnessed=$((t_harnessed + M_HARNESSED[$tee]))
  t_with_df=$((t_with_df + M_WITH_DF[$tee])); t_fetches=$((t_fetches + M_FETCHES[$tee]))
  t_merged=$((t_merged + M_MERGED[$tee]));    t_crashes=$((t_crashes + M_CRASHES[$tee]))
  t_distilled=$((t_distilled + M_DISTILLED[$tee]))
done
printf -- "----------------------------------------------------------------------------------------\n"
printf "%-10s %8s %10s %10s %12s %12s %10s %10s\n\n" \
  "all" "$t_tas" "$t_harnessed" "$t_with_df" "$t_fetches" "$t_merged" "$t_crashes" "$t_distilled"

if [[ -n "$json_out" ]]; then
  {
    echo "{"
    echo "  \"root\": \"$root_dir\","
    echo "  \"tees\": {"
    sep=""
    for tee in "${TEEs[@]}"; do
      printf '%s' "$sep"
      echo "    \"$tee\": {"
      echo "      \"tas\": ${M_TAS[$tee]},"
      echo "      \"tas_no_local_copy\": ${M_HARNESSED[$tee]},"
      echo "      \"tas_with_overlapped_fetches\": ${M_WITH_DF[$tee]},"
      echo "      \"overlapped_fetches\": ${M_FETCHES[$tee]},"
      echo "      \"overlapped_fetches_dedup\": ${M_FETCHES_DEDUP[$tee]},"
      echo "      \"overlapped_fetches_merged\": ${M_MERGED[$tee]},"
      echo "      \"crashes\": ${M_CRASHES[$tee]},"
      echo "      \"crashes_distilled\": ${M_DISTILLED[$tee]}"
      printf '    }'
      sep=$',\n'
    done
    echo ""
    echo "  },"
    echo "  \"all\": {"
    echo "    \"tas\": $t_tas,"
    echo "    \"tas_no_local_copy\": $t_harnessed,"
    echo "    \"tas_with_overlapped_fetches\": $t_with_df,"
    echo "    \"overlapped_fetches\": $t_fetches,"
    echo "    \"overlapped_fetches_merged\": $t_merged,"
    echo "    \"crashes\": $t_crashes,"
    echo "    \"crashes_distilled\": $t_distilled"
    echo "  }"
    echo "}"
  } > "$json_out"
  echo "[+] machine-readable results written to $json_out"
fi
