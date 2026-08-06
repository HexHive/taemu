#!/usr/bin/env bash
# Oversharing - on-device reproduction (Section V, Table III).
#
# Unlike ./ae.sh this does NOT run in docker: it needs USB access to the phones
# and the Android NDK on the host. It is the only part of the artifact that
# talks to real hardware.
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
#        ZERO-COPY      the TA wrote into the registered buffer *while*
#                       TEEC_InvokeCommand was still blocked, i.e. it operates
#                       on normal-world memory directly - Table III, claim C5
#        CRASHED        the TA died - the double fetch was exploited
#
# Usage:
#   ANDROID_NDK=~/opt/android-ndk-r26d ./ae_ondevice.sh            # all devices
#   ANDROID_NDK=... ./ae_ondevice.sh R58N349AKNY                   # one device
#   AE_ONDEVICE_RUNS=20 ./ae_ondevice.sh                           # more attempts
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

RUNS="${AE_ONDEVICE_RUNS:-5}"

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

    if ! ANDROID_SERIAL="$serial" make -C "$dir" phone >"$logf" 2>&1; then
        echo "build failed|see $(basename "$logf")"; return
    fi

    local out="" crashed=0 reached=0 nota=0 zerocopy=0 zcline="" i
    for i in $(seq 1 "$RUNS"); do
        out=$(adb -s "$serial" shell "su -c 'cd /data/local/tmp && chmod 755 poc && timeout 30 ./poc $pocargs 2>&1'" 2>&1 | tr -d '\r')
        printf '=== run %s\n%s\n' "$i" "$out" >>"$logf"
        case "$out" in
            *"OpenSession failed"*)  nota=1 ;;
            *Segmentation*|*"signal 11"*|*Abort*|*"TEE panic"*|*"tzdev: "*) crashed=1 ;;
        esac
        # A TA that answers an invocation while the racing thread rewrites the
        # registered buffer is the observation Table III is about.
        case "$out" in *"TEEC_Result:"*) reached=1 ;; esac
        case "$out" in
            *"ZEROCOPY: yes"*)
                zerocopy=1
                zcline=$(printf '%s' "$out" | grep -o "poll [0-9]* of [0-9]*" | tail -1)
                ;;
        esac
        # The watcher thread is not always scheduled before a short invoke
        # returns, so keep trying until it is; a crash ends it immediately.
        { [ "$crashed" = 1 ] || [ "$zerocopy" = 1 ]; } && break
    done

    local last; last=$(printf '%s' "$out" | grep -E "TEEC_Result|OpenSession failed" | tail -1)
    if   [ "$crashed" = 1 ];  then echo "CRASHED|$last"
    elif [ "$zerocopy" = 1 ]; then echo "ZERO-COPY|TA wrote into the buffer mid-invoke ($zcline)"
    elif [ "$reached" = 1 ];  then echo "reached|$last"
    elif [ "$nota" = 1 ];     then echo "no TA|TEEC_OpenSession failed"
    else                           echo "no result|see $(basename "$logf")"; fi
}

# ----------------------------------------------------------------------------- main
main() {
    command -v adb >/dev/null || die "adb is required"
    [ -n "${ANDROID_NDK:-}" ] || die "set ANDROID_NDK (e.g. ~/opt/android-ndk-r26d)"
    [ -x "$ANDROID_NDK/ndk-build" ] || die "no ndk-build in $ANDROID_NDK"
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
                CRASHED|ZERO-COPY) ok "$(basename "$poc"): $verdict - $detail" ;;
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
