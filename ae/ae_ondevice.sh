#!/usr/bin/env bash
# Oversharing - on-device reproduction (Section V, Table III).
#
# Unlike ./ae.sh this does NOT run in docker: it needs USB access to the phones.
# It is the only part of the artifact that talks to real hardware.
#
# The proof-of-concept clients are shipped prebuilt for arm64 in
# ae/prebuilt/ondevice/, so no Android NDK is needed to run them. Set
# ANDROID_NDK and AE_ONDEVICE_BUILD=1 to rebuild from source instead (which
# also refreshes the prebuilt copies).
#
# For every connected device it
#   1. identifies the TEE (client library, device nodes, SoC),
#   2. builds the proof-of-concept clients that target that TEE and pushes them,
#   3. runs each one and classifies what happened:
#
#        no TA          TEEC_OpenSession failed - that TA is not installed here
#        reached        the TA processed a memref that a second thread kept
#                       rewriting for the whole call, but nothing observable
#                       came back
#        DOUBLE-FETCH   the TA demonstrably read the same field twice and got
#                       two different values - Table III, claim C5
#        CRASHED        the TA died - the double fetch was exploited
#
# How a double fetch is observed differs per TEE, because it depends on what
# the TA makes visible (Appendix A of the paper):
#
#   kinibi  df1e   the TA logs its first fetch and then the branch it took on
#                  the second one, and its logs go to the kernel log. A pair
#                  like "cmd : 0x1009" followed by ..._get_hmackey_... is only
#                  possible if the value changed in between.
#   qsee    a985   the TA returns -5 when both fetches agree and -24
#                  (0xffffffe8) only if they disagree.
#   teegris s10    the registered buffer is watched from a third thread; a
#                  change while TEEC_InvokeCommand is still blocked means the
#                  TA writes into normal-world memory. (The paper establishes
#                  TEEGris from an on-device crash of a Table II TA instead;
#                  that TA is not on every Samsung phone.)
#
# Usage:
#   ./ae_ondevice.sh                                        # every device
#   ./ae_ondevice.sh R58N349AKNY                            # one of them
#   AE_ONDEVICE_RUNS=50 ./ae_ondevice.sh                    # more attempts
#   AE_ONDEVICE_BUILD=1 ANDROID_NDK=~/opt/android-ndk-r26d ./ae_ondevice.sh
#
# Results: ae/results/ondevice/{ondevice.txt,csv,tex}, per-run logs beside them.
set -uo pipefail

AE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$AE_DIR/.." && pwd)"
RES_DIR="$AE_DIR/results/ondevice"

C_RED=$'\e[1;31m'; C_GRN=$'\e[1;32m'; C_BLU=$'\e[1;34m'; C_RST=$'\e[0m'
log() { echo "${C_BLU}[ae]${C_RST} $*"; }
ok()  { echo "${C_GRN}[ok]${C_RST} $*"; }
err() { echo "${C_RED}[--]${C_RST} $*"; }

RUNS="${AE_ONDEVICE_RUNS:-25}"
BUILD="${AE_ONDEVICE_BUILD:-0}"
PREBUILT="$AE_DIR/prebuilt/ondevice"

# ---------------------------------------------------------------- proof of concepts
# poc dir | TEE | TA UUID | extra argv for ./poc
# The argv column carries the per-firmware constants a PoC needs; see the PoC
# source for what they mean.
# The first entry per TEE is the zero-copy probe of claim C5: it races a memref
# and reports whether the TA writes into it mid-call. The rest are the Table II
# vulnerabilities, which only reproduce on a phone that ships the vulnerable TA.
POCS=(
  "teegris/pocs/s10_5345_SECFR|teegris|00000000-0000-0000-0000-5345435f4652|0x212010 0x11"
  "qsee/pocs/a985_test|qsee|A985D3EB-3B52-4D44-BE6C-628A813561E8|"
  "beanpod/pocs/df1e_test|kinibi|df1edda8627911e980ae507b9d9a7e7d|"
  "beanpod/pocs/0801_df_oob|beanpod|08010203000000000000000000000000|"
  "teegris/pocs/4662_FbCkmR_df|teegris|00000000-0000-0000-0000-4662436b6d52|"
  "mitee/pocs/377e_double_fetch_stackov|mitee|377ee4e8-af0e-474f-a9d636a9268fe85c|"
  "mitee/pocs/88ce_df_oobr|mitee|88ce8e6b-8646-4092-bb78faf5b55ff4df|"
  "mitee/pocs/3d08_df_memsetoob|mitee|3d08821c-33a6-11e6-a1fa089e01c83aa2|"
  "mitee/pocs/3d08_doublefree|mitee|3d08821c-33a6-11e6-a1fa089e01c83aa2|"
)

die() { err "$*"; exit 1; }

# ------------------------------------------------------------------- device probing
device_tee() {
    # Which TEE does this device run? Decided by the client library the PoCs
    # dlopen() plus the kernel device node the driver exposes.
    local s="$1"
    adb -s "$s" shell 'su -c "
        if [ -e /vendor/lib64/libteecl.so ] && [ -e /dev/tzdev ]; then echo teegris
        elif [ -e /vendor/lib64/libGPTEE_vendor.so ] || [ -e /dev/qseecom ]; then echo qsee
        elif [ -e /dev/mobicore ] || [ -e /dev/mcd ]; then echo kinibi
        elif [ -e /dev/mitee ] || [ -e /vendor/lib64/libmitee.so ]; then echo mitee
        elif [ -e /dev/tee0 ] || [ -e /vendor/lib64/libteec.so ]; then echo beanpod
        else echo unknown; fi"' 2>/dev/null | tr -d '\r' | head -1
}

device_model() {
    adb -s "$1" shell 'getprop ro.product.manufacturer; getprop ro.product.model' \
        2>/dev/null | tr -d '\r' | paste -sd' ' -
}

device_rooted() {
    [ "$(adb -s "$1" shell 'su -c id' 2>/dev/null | tr -d '\r' | grep -c 'uid=0')" -gt 0 ]
}

# ------------------------------------------------------------------------ one PoC
run_poc() {
    # run_poc <serial> <poc dir> <argv> -> prints "<verdict>|<detail>"
    local serial="$1" poc="$2" pocargs="$3"
    local dir="$REPO_DIR/$poc" name; name="$(basename "$poc")"
    local logf="$RES_DIR/${serial}_${name}.log"

    if [ "$BUILD" = 1 ]; then
        if ! ANDROID_SERIAL="$serial" make -C "$dir" phone >"$logf" 2>&1; then
            echo "build failed|see $(basename "$logf")"; return
        fi
        cp "$dir/libs/arm64-v8a/poc" "$PREBUILT/$name" 2>/dev/null
    else
        [ -f "$PREBUILT/$name" ] || {
            echo "no binary|$PREBUILT/$name is missing, rebuild with AE_ONDEVICE_BUILD=1"
            return
        }
        if ! adb -s "$serial" push "$PREBUILT/$name" /data/local/tmp/poc >"$logf" 2>&1; then
            echo "push failed|see $(basename "$logf")"; return
        fi
    fi

    local out="" klog="" crashed=0 reached=0 nota=0 df=0 dfline="" i
    for i in $(seq 1 "$RUNS"); do
        # Clear the kernel log first: the Kinibi TA writes its own trace there.
        adb -s "$serial" shell "su -c 'dmesg -c'" >/dev/null 2>&1
        out=$(adb -s "$serial" shell "su -c 'cd /data/local/tmp && chmod 755 poc && timeout 30 ./poc $pocargs 2>&1'" 2>&1 | tr -d '\r')
        klog=$(adb -s "$serial" shell "su -c 'dmesg'" 2>/dev/null | tr -d '\r' | sed 's/.*|//')
        printf '=== run %s\n%s\n--- kernel log\n%s\n' "$i" "$out" \
               "$(printf '%s' "$klog" | grep -E 'InvokeCommandEntryPoint|cmd : 0x|hmackey|check_key' || true)" >>"$logf"
        case "$out" in
            *"OpenSession failed"*)  nota=1 ;;
            *Segmentation*|*"signal 11"*|*Abort*|*"TEE panic"*|*"tzdev: "*) crashed=1 ;;
        esac
        # A TA that answers an invocation while the racing thread rewrites the
        # registered buffer is the observation Table III is about.
        case "$out" in *"TEEC_Result:"*) reached=1 ;; esac
        # kinibi: first fetch logged, then the branch the second fetch took.
        # Only look at the last invocation in the log: dmesg -c is not
        # guaranteed to have cleared anything, and a pair carried over from an
        # earlier run would be a false positive.
        local inv first branch
        inv=$(printf '%s' "$klog" | awk '/TA_InvokeCommandEntryPoint/ {buf = ""} {buf = buf $0 "\n"} END {printf "%s", buf}')
        first=$(printf '%s' "$inv" | grep -oE "cmd : 0x1[0-9a-f]+" | tail -1)
        branch=$(printf '%s' "$inv" | grep -oE "paytrigger_(ta_get_hmackey|check_key)[a-z_]*" | tail -1)
        if [ -n "$first" ] && [ -n "$branch" ]; then
            case "$first:$branch" in
                *0x1001:*check_key*|*0x1009:*get_hmackey*)
                    df=1; dfline="$first then $branch" ;;
            esac
        fi
        # qsee: -24 is only reachable when the two fetches disagree.
        case "$out" in
            *"TEEC_Result: ffffffe8"*) df=1; dfline="TA returned -24" ;;
        esac
        # teegris: the TA wrote into the registered buffer mid-invoke.
        case "$out" in
            *"ZEROCOPY: yes"*)
                df=1
                dfline="TA wrote into the buffer mid-invoke, $(printf '%s' "$out" | grep -o 'poll [0-9]* of [0-9]*' | tail -1)"
                ;;
        esac
        # Winning the race is probabilistic, so keep going until it lands.
        { [ "$crashed" = 1 ] || [ "$df" = 1 ]; } && break
    done

    local last; last=$(printf '%s' "$out" | grep -E "TEEC_Result|OpenSession failed" | tail -1)
    if   [ "$crashed" = 1 ]; then echo "CRASHED|$last"
    elif [ "$df" = 1 ];      then echo "DOUBLE-FETCH|$dfline (run $i of $RUNS)"
    elif [ "$reached" = 1 ]; then echo "reached|$last"
    elif [ "$nota" = 1 ];    then echo "no TA|TEEC_OpenSession failed"
    else                          echo "no result|see $(basename "$logf")"; fi
}

# ----------------------------------------------------------------------------- main
main() {
    command -v adb >/dev/null || die "adb is required"
    if [ "$BUILD" = 1 ]; then
        [ -n "${ANDROID_NDK:-}" ] || die "AE_ONDEVICE_BUILD=1 needs ANDROID_NDK"
        [ -x "$ANDROID_NDK/ndk-build" ] || die "no ndk-build in $ANDROID_NDK"
        mkdir -p "$PREBUILT"
    fi
    mkdir -p "$RES_DIR"

    # adb separates serial and state with a tab, so split on whitespace.
    local wanted=("$@") serials=() serial state
    while read -r serial state; do
        [ -z "$serial" ] && continue
        if [ "$state" != "device" ]; then
            err "$serial: $state - accept the USB debugging prompt on the phone"
            continue
        fi
        if [ ${#wanted[@]} -gt 0 ]; then
            case " ${wanted[*]} " in *" $serial "*) ;; *) continue ;; esac
        fi
        serials+=("$serial")
    done < <(adb devices | tail -n +2 | awk 'NF >= 2 {print $1, $2}')

    [ ${#serials[@]} -gt 0 ] || die "no usable device (adb devices)"

    local rows=() csv="$RES_DIR/ondevice.csv"
    echo "serial,device,tee,rooted,poc,ta,verdict,detail" >"$csv"

    for serial in "${serials[@]}"; do
        local model tee rooted
        model=$(device_model "$serial")
        tee=$(device_tee "$serial")
        if device_rooted "$serial"; then rooted=yes; else rooted=no; fi
        log "$serial  $model  tee=$tee  root=$rooted"
        if [ "$rooted" != yes ]; then
            err "$serial: not rooted - the PoCs need root to reach the TEE driver"
        fi

        local ran=0 entry poc ptee uuid pargs verdict detail
        for entry in "${POCS[@]}"; do
            IFS='|' read -r poc ptee uuid pargs <<<"$entry"
            [ "$ptee" = "$tee" ] || continue
            [ -d "$REPO_DIR/$poc" ] || continue
            ran=$((ran + 1))
            IFS='|' read -r verdict detail < <(run_poc "$serial" "$poc" "$pargs")
            case "$verdict" in
                CRASHED|DOUBLE-FETCH) ok "$(basename "$poc"): $verdict - $detail" ;;
                reached) ok "$(basename "$poc"): $verdict - $detail" ;;
                *)       err "$(basename "$poc"): $verdict - $detail" ;;
            esac
            rows+=("$serial|$model|$tee|$(basename "$poc")|$uuid|$verdict|$detail")
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "$serial" "$model" "$tee" "$rooted" "$(basename "$poc")" \
                "$uuid" "$verdict" "${detail//,/ }" >>"$csv"
        done
        [ "$ran" -gt 0 ] || err "$serial: no proof-of-concept targets $tee"
    done

    # ------------------------------------------------------------------ the table
    {
        echo "On-device reproduction (Section V)"
        echo "=================================="
        echo
        printf "%-16s %-22s %-8s %-26s %-9s %s\n" \
               DEVICE MODEL TEE POC VERDICT DETAIL
        printf "%s\n" "----------------------------------------------------------------------------------------------------"
        local r
        for r in "${rows[@]}"; do
            IFS='|' read -r s m t p _ v d <<<"$r"
            printf "%-16s %-22s %-8s %-26s %-9s %s\n" "$s" "$m" "$t" "$p" "$v" "$d"
        done
    } | tee "$RES_DIR/ondevice.txt"

    echo
    echo "  $(realpath --relative-to="$REPO_DIR" "$RES_DIR/ondevice.txt")"
    echo "  $(realpath --relative-to="$REPO_DIR" "$csv")"
}

main "$@"
