#!/usr/bin/env bash
#
# Reproducible build for the OP-TEE shared-memory-mitigation benchmark.
#
# The mitigation (optee_os.patch) lives entirely in libutee (the TA-side
# runtime: user_ta_entry.c / tee_api.c / tee_internal_api.h), which is
# statically linked into every TA. The OP-TEE core image is therefore
# UNCHANGED between "with" and "without" the mitigation -- the only difference
# is which TA dev-kit the benchmark TA is linked against. So we:
#
#   1. build the baseline (unpatched) TA dev-kit         -> devkit_base
#   2. apply optee_os.patch + strip its debug EMSGs, and
#      build the mitigated TA dev-kit                    -> devkit_mitig
#   3. build the benchmark TA twice (baseline / mitigated UUID)
#   4. build the benchmark host binary against optee_client
#
# The three measured configurations are then all exercised on the SAME core
# image at runtime (see harness/driver.py):
#   - baseline TA                       (no mitigation code at all)
#   - mitigated TA, command SHARED (1)  (opted in  -> direct shared access)
#   - mitigated TA, command COPIED (0)  (not opted -> copy-in/copy-out)
#
set -euo pipefail

# --- paths (edit to taste) --------------------------------------------------
HERE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PATCH_DIR=${PATCH_DIR:-$(cd "$HERE_DIR/.." && pwd)}
DF=${DF:-/home/philipp/taemu/df}
BASE_TREE=${BASE_TREE:-$DF/optee}         # clean OP-TEE tree (baseline)
MITIG_TREE=${MITIG_TREE:-$DF/optee_patch} # OP-TEE tree that receives optee_os.patch
OUT=${OUT:-$PATCH_DIR/benchmark/out}   # writable build output (not root-owned)

TC64=$BASE_TREE/toolchains/aarch64/bin/aarch64-linux-gnu-
SYSROOT=$BASE_TREE/out-br/host/aarch64-buildroot-linux-gnu/sysroot
HERE=$PATCH_DIR/benchmark

mkdir -p "$OUT"/devkit_base "$OUT"/devkit_mitig "$OUT"/ta_base "$OUT"/ta_mitig "$OUT"/share

devkit () {  # $1 = optee_os path, $2 = output dir
    make -C "$1" -j"$(nproc)" O="$2" \
        PLATFORM=vexpress-qemu_armv8a \
        CFG_USER_TA_TARGETS=ta_arm64 CFG_ARM64_core=y CFG_ARM_GICV3=y \
        CROSS_COMPILE="$TC64" CROSS_COMPILE_core="$TC64" \
        CROSS_COMPILE_ta_arm64="$TC64" \
        CFG_TEE_CORE_LOG_LEVEL=3 DEBUG=0 ta_dev_kit
}

echo "==> [1] baseline dev-kit"
devkit "$BASE_TREE/optee_os" "$OUT/devkit_base"

echo "==> [2] apply mitigation patch (+ strip hot-path debug EMSGs)"
git -C "$MITIG_TREE/optee_os" apply "$PATCH_DIR/optee_os.patch" || \
    echo "   (patch may already be applied; continuing)"
# Debug EMSG()s in the mitigation hot path would write to the secure serial
# console on every invocation and completely dominate timing; they are debug
# artifacts, not part of the mitigation, so remove them for benchmarking.
sed -i -E '/EMSG\("(new InvokeShm|inserting new command|InvokeShms is NULL|cur: %p|cur->commandID|matching commandID|commandID not found)/d' \
    "$MITIG_TREE/optee_os/lib/libutee/tee_api.c"
sed -i -E '/EMSG\("(tmpBufs\[n\]= %p|size: %p, tmpBufs)/d' \
    "$MITIG_TREE/optee_os/lib/libutee/user_ta_entry.c"

echo "==> [2] mitigated dev-kit"
devkit "$MITIG_TREE/optee_os" "$OUT/devkit_mitig"

echo "==> [3] benchmark TAs"
make -C "$HERE/bench_ta" O="$OUT/ta_base" CROSS_COMPILE="$TC64" \
    TA_DEV_KIT_DIR="$OUT/devkit_base/export-ta_arm64" \
    BINARY=11111111-1111-1111-1111-111111111111
make -C "$HERE/bench_ta" O="$OUT/ta_mitig" CROSS_COMPILE="$TC64" \
    TA_DEV_KIT_DIR="$OUT/devkit_mitig/export-ta_arm64" \
    BENCH_CFLAGS=-DMITIG \
    BINARY=22222222-2222-2222-2222-222222222222

echo "==> [4] benchmark host binaries"
"$TC64"gcc --sysroot="$SYSROOT" -O2 -Wall \
    -o "$OUT/share/optee_shm_bench" "$HERE/bench_host/main.c" \
    -I"$SYSROOT/usr/include" -L"$SYSROOT/usr/lib" -lteec
# Functional double-fetch probe (races the memref from a second thread).
"$TC64"gcc --sysroot="$SYSROOT" -O2 -Wall \
    -o "$OUT/share/optee_shm_dftest" "$HERE/bench_host/df_main.c" \
    -I"$SYSROOT/usr/include" -L"$SYSROOT/usr/lib" -lteec -lpthread

cp "$OUT/ta_base"/*.ta "$OUT/ta_mitig"/*.ta "$OUT/share/"

echo "==> [5] QEMU run dir (boot images, resolving container-path symlinks)"
# out/bin symlinks point at the Docker path /optee; re-point them at $BASE_TREE.
RUNDIR="$OUT/run"; mkdir -p "$RUNDIR"
ln -sf "$BASE_TREE/trusted-firmware-a/build/qemu/release/bl1.bin"  "$RUNDIR/bl1.bin"
ln -sf "$BASE_TREE/trusted-firmware-a/build/qemu/release/bl2.bin"  "$RUNDIR/bl2.bin"
ln -sf "$BASE_TREE/trusted-firmware-a/build/qemu/release/bl31.bin" "$RUNDIR/bl31.bin"
ln -sf "$BASE_TREE/optee_os/out/arm/core/tee-header_v2.bin"   "$RUNDIR/bl32.bin"
ln -sf "$BASE_TREE/optee_os/out/arm/core/tee-pager_v2.bin"    "$RUNDIR/bl32_extra1.bin"
ln -sf "$BASE_TREE/optee_os/out/arm/core/tee-pageable_v2.bin" "$RUNDIR/bl32_extra2.bin"
ln -sf "$BASE_TREE/u-boot/u-boot.bin"                 "$RUNDIR/bl33.bin"
ln -sf "$BASE_TREE/linux/arch/arm64/boot/Image"       "$RUNDIR/Image"
ln -sf "$BASE_TREE/out/bin/uImage"                    "$RUNDIR/uImage"
ln -sf "$BASE_TREE/out-br/images/rootfs.cpio.gz"      "$RUNDIR/rootfs.cpio.gz"
ln -sf "$BASE_TREE/out/bin/rootfs.cpio.uboot"         "$RUNDIR/rootfs.cpio.uboot"

echo "==> done."
echo "    Run the benchmark with:  OPTEE_DIR=$BASE_TREE BENCH_OUT=$OUT python3 harness/driver.py"
