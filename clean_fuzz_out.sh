#!/usr/bin/env bash
#
# Wipe generated fuzzing output from every harness directory in the repo.
#
# Removes, per <tee>/harness{,_dev}/<name>/:
#   out/                        afl-fuzz output (default/, fuzzerNN/, cov/)
#   df_fuzz/                    df_fuzz.sh campaigns (run:id:<seed>_<reghash>/{in,out})
#   in/suspicious_inputs/       recorder output (--fuzz)
#   in/suspicious_inputs_replay/    recorder output (--fuzz_replay)
#   record_meta/                per-run record metadata
#   campaign_out/               eval/fuzz.py campaign iterations
#   api_cov/                    eval/cov_api.py replay coverage
#   logs/                       per-harness emulator logs
#   drcov.log                   merged drcov trace
#   __pycache__/                harness.py bytecode
#
# The seed corpus in in/ is kept unless --seeds is given.
#
# Dry-run by default; pass --force to actually delete.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

YELLOW=$'\e[1;33m'; CYAN=$'\e[1;36m'; GREEN=$'\e[1;32m'; RED=$'\e[1;31m'; RESET=$'\e[0m'

# Directories/files generated inside a harness dir. Order matters only for output.
TARGETS=(
    out
    df_fuzz
    in/suspicious_inputs
    in/suspicious_inputs_replay
    record_meta
    campaign_out
    api_cov
    logs
    drcov.log
    __pycache__
)

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] [harness-dir ...]

Wipes fuzzing output from every <tee>/harness{,_dev}/<name>/ in the repo, or
from just the harness directories given as arguments.

Options:
  -f, --force        actually delete (default is a dry run)
  -y, --yes          with --force, do not ask for confirmation
  -t, --tee NAME     only this TEE directory (repeatable), e.g. -t mitee -t beanpod
  -k, --keep GLOB    skip harness dirs whose name matches GLOB (repeatable)
  -s, --seeds        also clear the seed corpus in in/ (kept by default)
  -h, --help         this message

Examples:
  $(basename "$0")                        # show what would be deleted, repo-wide
  $(basename "$0") --force --yes          # wipe everything, no prompt
  $(basename "$0") -t mitee -f            # only mitee harnesses
  $(basename "$0") -f mitee/harness/377e_fuzz
  $(basename "$0") -f -k '*_poc' -k '*_df'   # keep PoC/df harnesses untouched
EOF
}

FORCE=0
ASSUME_YES=0
WIPE_SEEDS=0
TEES=()
KEEP=()
EXPLICIT=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--force)   FORCE=1; shift ;;
        -y|--yes)     ASSUME_YES=1; shift ;;
        -s|--seeds)   WIPE_SEEDS=1; shift ;;
        -n|--dry-run) FORCE=0; shift ;;
        -t|--tee)     [[ $# -ge 2 ]] || { echo "${RED}error:${RESET} --tee needs a value" >&2; exit 1; }; TEES+=("$2"); shift 2 ;;
        -k|--keep)    [[ $# -ge 2 ]] || { echo "${RED}error:${RESET} --keep needs a value" >&2; exit 1; }; KEEP+=("$2"); shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; EXPLICIT+=("$@"); break ;;
        -*)           echo "${RED}error:${RESET} unknown option $1" >&2; usage >&2; exit 1 ;;
        *)            EXPLICIT+=("$1"); shift ;;
    esac
done

(( WIPE_SEEDS )) && TARGETS+=(in)

# ---- collect harness directories -------------------------------------------
harnesses=()
if [[ ${#EXPLICIT[@]} -gt 0 ]]; then
    for d in "${EXPLICIT[@]}"; do
        if [[ ! -d "$d" ]]; then
            echo "${RED}error:${RESET} not a directory: $d" >&2
            exit 1
        fi
        harnesses+=("$(cd -- "$d" && pwd -P)")
    done
else
    search_roots=()
    if [[ ${#TEES[@]} -gt 0 ]]; then
        for t in "${TEES[@]}"; do
            if [[ -d "$ROOT/$t" ]]; then
                search_roots+=("$ROOT/$t")
            else
                echo "${YELLOW}warning:${RESET} no such TEE directory: $t" >&2
            fi
        done
        [[ ${#search_roots[@]} -eq 0 ]] && { echo "${RED}error:${RESET} no valid --tee given" >&2; exit 1; }
    else
        search_roots=("$ROOT")
    fi

    depth_args=(-mindepth 3 -maxdepth 3)
    [[ ${#TEES[@]} -gt 0 ]] && depth_args=(-mindepth 2 -maxdepth 2)

    while IFS= read -r -d '' d; do
        harnesses+=("$d")
    done < <(find "${search_roots[@]}" "${depth_args[@]}" -type d \
                  \( -path '*/harness/*' -o -path '*/harness_dev/*' \) -print0 \
             2>/dev/null | sort -z)
fi

# apply --keep filters
if [[ ${#KEEP[@]} -gt 0 && ${#harnesses[@]} -gt 0 ]]; then
    filtered=()
    for h in "${harnesses[@]}"; do
        skip=0
        for g in "${KEEP[@]}"; do
            # shellcheck disable=SC2053
            [[ "$(basename "$h")" == $g ]] && { skip=1; break; }
        done
        (( skip )) || filtered+=("$h")
    done
    harnesses=("${filtered[@]}")
fi

if [[ ${#harnesses[@]} -eq 0 ]]; then
    echo "${YELLOW}No harness directories found.${RESET}"
    exit 0
fi

# ---- collect deletion targets ----------------------------------------------
victims=()
for h in "${harnesses[@]}"; do
    for t in "${TARGETS[@]}"; do
        p="$h/$t"
        [[ -e "$p" ]] && victims+=("$p")
    done
done

if [[ ${#victims[@]} -eq 0 ]]; then
    echo "${GREEN}Nothing to clean${RESET} (scanned ${#harnesses[@]} harness dirs)."
    exit 0
fi

total=0
for p in "${victims[@]}"; do
    sz=$(du -sb -- "$p" 2>/dev/null | cut -f1)
    total=$(( total + ${sz:-0} ))
    printf '  %s%s%s\n' "$CYAN" "${p#"$ROOT"/}" "$RESET"
done

if command -v numfmt >/dev/null 2>&1; then
    human=$(numfmt --to=iec --suffix=B "$total")
else
    human="${total} bytes"
fi

echo
echo "${YELLOW}${#victims[@]}${RESET} paths in ${YELLOW}${#harnesses[@]}${RESET} harness dirs, ${YELLOW}${human}${RESET} total."
(( WIPE_SEEDS )) && echo "${RED}--seeds given: the seed corpus in in/ will be cleared too.${RESET}"

if (( ! FORCE )); then
    echo "${GREEN}Dry run — nothing deleted.${RESET} Re-run with ${YELLOW}--force${RESET} to delete."
    exit 0
fi

if (( ! ASSUME_YES )); then
    # -r /dev/tty is true even with no controlling terminal; the open is what fails
    if ! { : </dev/tty; } 2>/dev/null; then
        echo "${RED}Aborted:${RESET} no terminal to confirm on — pass ${YELLOW}--yes${RESET} to delete non-interactively."
        exit 1
    fi
    read -r -p "Delete these ${#victims[@]} paths? (y/N): " reply </dev/tty
    case "${reply:-n}" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "${RED}Aborted.${RESET}"; exit 1 ;;
    esac
fi

failed=0
for p in "${victims[@]}"; do
    if [[ "$(basename "$p")" == "in" ]]; then
        # keep the directory itself, drop its contents (afl needs a non-empty in/)
        rm -rf -- "${p:?}"/* "${p:?}"/.[!.]* 2>/dev/null
    else
        rm -rf -- "${p:?}" || { echo "${RED}failed:${RESET} $p" >&2; failed=1; }
    fi
done

if (( failed )); then
    echo "${RED}Finished with errors.${RESET}"
    exit 1
fi
echo "${GREEN}Cleaned ${#victims[@]} paths (${human}).${RESET}"
