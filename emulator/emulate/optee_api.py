"""OP-TEE syscall dispatcher.

The TA's statically-linked libutee issues kernel calls via `mov x8, #SCN; svc
#0`. We register :func:`optee_syscall` on the SVC interrupt (intno 2) and play
the kernel: read the SCN from x8, dispatch to a handler (see
:mod:`.optee.syscalls`), and write the TEE_Result into x0. After the interrupt
hook returns, unicorn resumes at the `ret` following the `svc`.

Two SCNs are terminal and handled here directly:
  * RETURN (0) — `__utee_entry` finished; capture the result and stop emulation.
  * PANIC  (2) — the TA panicked; flag a crash and stop.
"""

import os
import hashlib

from qiling import Qiling

from .optee import numbers as scn
from .optee.syscalls import SYSCALLS
from .common import crash, crash_notimpl, finalize_fuzzing, AFL_EXIT_PC
from .fuzz_record import Status
from .gp.utils.err import TEE_ERROR_NOT_IMPLEMENTED


# --- ARM/MediaTek CryptoCell secure-element emulation -----------------------
# DJI TAs reach the CryptoCell hardware through OP-TEE *vendor* syscalls (scn
# 74/75/88 in their OP-TEE fork). The real silicon derives keys from per-device
# fused secrets we don't have, so we emulate the hardware-facing syscalls:
# report a life-cycle state and hand back deterministic (reproducible) key
# material, so flows like fw_util's TA_KeyDerivation run end to end instead of
# dead-ending on an unhandled syscall.
#
# NOTE: these numbers overlap the standard 0..93 SCN space; they are treated as
# vendor calls because the DJI TAs use them that way. Override the reported
# life-cycle state with TAEMU_CC_LCS (default: Secure).
CC_LCS_CM = 0      # Chip Manufacture
CC_LCS_DM = 1      # Device Manufacture
CC_LCS_SECURE = 5  # Secure / production device -> uses the CryptoCell KDF path
CC_LCS_RMA = 7


def _cc_lcs():
    try:
        return int(os.environ.get("TAEMU_CC_LCS", CC_LCS_SECURE), 0) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return CC_LCS_SECURE


def _cc_seed(ql, *regs):
    """Stable per-call-site seed from register values (no memory reads)."""
    seed = b"taemu-cryptocell"
    for r in regs:
        seed += int(r).to_bytes(8, "little")
    return seed


def _cc_fill(ql, ptr, length, seed):
    """Write `length` bytes of deterministic pseudo key material at `ptr`."""
    if not ptr or length <= 0:
        return
    length = min(int(length), 0x2000)
    blob = b""
    ctr = 0
    while len(blob) < length:
        blob += hashlib.sha256(seed + ctr.to_bytes(4, "little")).digest()
        ctr += 1
    try:
        ql.mem.write(ptr, blob[:length])
    except Exception as e:  # pragma: no cover - defensive
        ql.log.warning(f"[cryptocell] write {length:#x} bytes @ {ptr:#x} failed: {e}")


def _cc_get_lcs(ql):
    # scn 75 (0x4b): TEE_CryptoCell_GetLCS(uint32_t *lcs)
    out = ql.arch.regs.x0
    if out:
        ql.mem.write(out, _cc_lcs().to_bytes(4, "little"))
    return 0


def _cc_key_derivation(ql):
    # scn 74 (0x4a): TEE_CryptoCell_KeyDerivation(mode, label, n, ctx, ctxlen, out, outlen)
    _cc_fill(ql, ql.arch.regs.x5, ql.arch.regs.x6,
             _cc_seed(ql, ql.arch.regs.x1, ql.arch.regs.x3, ql.arch.regs.x5))
    return 0


def _cc_prak_get(ql):
    # scn 88 (0x58): TEE_PRAK_Get(out, *len) -- platform RoT auth key
    out = ql.arch.regs.x0
    lenp = ql.arch.regs.x1
    n = 0x20
    if lenp:
        try:
            n = int.from_bytes(ql.mem.read(lenp, 4), "little")
        except Exception:
            n = 0x20
    _cc_fill(ql, out, n, _cc_seed(ql, ql.arch.regs.x0, ql.arch.regs.x1))
    return 0


# vendor syscall number -> handler(ql) returning the x0 result value
CRYPTOCELL_SYSCALLS = {
    74: _cc_key_derivation,  # TEE_CryptoCell_KeyDerivation
    75: _cc_get_lcs,         # TEE_CryptoCell_GetLCS
    88: _cc_prak_get,        # TEE_PRAK_Get
}


def optee_syscall(ql: Qiling, intno, emu):
    syscall_nr = int(ql.arch.regs.x8)
    name = scn.scn_name(syscall_nr)

    # --- terminal syscalls --------------------------------------------------
    if syscall_nr == scn.TEE_SCN_RETURN:
        emu.utee_result = int(ql.arch.regs.x0) & 0xFFFFFFFF
        emu.utee_returned = True
        ql.log.info(f"[optee] RETURN -> {emu.utee_result:#x}")
        # record suspicious (e.g. overlapping double-fetch) inputs at the
        # natural end of an entry, replacing the old TA_*EntryPoint_end hook.
        if getattr(emu, "status", None) in (Status.FUZZING, Status.REPLAYING):
            finalize_fuzzing(ql, "utee_return")
        ql.arch.regs.arch_pc = AFL_EXIT_PC
        ql.emu_stop()
        return

    if syscall_nr == scn.TEE_SCN_PANIC:
        emu.utee_panicked = True
        emu.utee_panic_code = int(ql.arch.regs.x0) & 0xFFFFFFFF
        ql.log.critical(f"[optee] TA PANIC code={emu.utee_panic_code:#x}")
        crash(ql, f"TA_panic({emu.utee_panic_code:#x})")
        ql.emu_stop()
        return

    # --- standard syscalls --------------------------------------------------
    handler = SYSCALLS.get(syscall_nr)
    if handler is not None:
        res = int(handler(ql, emu)) & 0xFFFFFFFF
        ql.arch.regs.x0 = res
        ql.log.debug(f"[optee] {name} ({syscall_nr}) -> {res:#x}")
        return

    # --- DJI CryptoCell vendor syscalls ------------------------------------
    if syscall_nr in CRYPTOCELL_SYSCALLS:
        ret = CRYPTOCELL_SYSCALLS[syscall_nr](ql) & 0xFFFFFFFF
        ql.arch.regs.x0 = ret
        ql.log.info(f"[optee][cryptocell] vendor syscall {syscall_nr} -> {ret:#x}")
        return

    # --- unimplemented ------------------------------------------------------
    ql.log.warning(f"[optee] syscall {syscall_nr} ({name}) not implemented")
    if emu.crash_on_not_implemented:
        crash_notimpl(ql, f"optee syscall {syscall_nr} ({name}) not implemented")
        return
    # Gracefully fail so emulation survives unimplementable/vendor syscalls: the
    # TA just sees the operation fail.
    ql.arch.regs.x0 = TEE_ERROR_NOT_IMPLEMENTED
    return


# --- retained from df-detector's optee_api ---
def _ZN3std9panicking20rust_panic_with_hook17h5774058f964c35abE(ql: Qiling, hook_data):
    ql.log.info("[optee] panic handler")
    ql.emu_stop()

"""

def qsee_is_sw_fuse_blown(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
            {"idk": INT, "out": POINTER}
        )
    ql.mem.write(p["out"], 4*b"\x00")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
"""
