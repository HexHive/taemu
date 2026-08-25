"""Kernel-side implementations of the OP-TEE TA syscalls.

Each handler has the signature ``handler(ql, emu) -> TEE_Result`` and reads its
arguments from x0..x7 (the syscall ABI) and writes outputs back through guest
pointers. The dispatcher in :mod:`..optee_api` writes the returned result into
x0. RETURN and PANIC are handled directly in the dispatcher because they stop
emulation.

Coverage is incremental: the infrastructure syscalls needed to bring a TA up
through create/open/invoke are implemented here; storage/crypto/object syscalls
are added as the target TAs exercise them, reusing the logic in ``..gp``. Any
unmapped SCN is logged and graceful-failed so emulation keeps running.
"""

from qiling import Qiling

from . import numbers as scn
from ..gp.utils.err import *


# ---------------------------------------------------------------------------
# infrastructure syscalls
# ---------------------------------------------------------------------------
def sys_log(ql: Qiling, emu):
    # _utee_log(const void *buf, size_t len)
    buf = ql.arch.regs.x0
    length = ql.arch.regs.x1
    try:
        out = ql.mem.read(buf, length).decode("utf-8", errors="replace")
    except Exception:
        return TEE_SUCCESS
    ql.log.info(f"[ta-log] {out.rstrip()}")
    return TEE_SUCCESS


def sys_get_cancellation_flag(ql: Qiling, emu):
    # _utee_get_cancellation_flag(uint32_t *cancel)
    out = ql.arch.regs.x0
    if out:
        ql.mem.write(out, (0).to_bytes(4, "little"))
    return TEE_SUCCESS


def sys_unmask_cancellation(ql: Qiling, emu):
    out = ql.arch.regs.x0
    if out:
        ql.mem.write(out, (0).to_bytes(4, "little"))
    return TEE_SUCCESS


def sys_mask_cancellation(ql: Qiling, emu):
    out = ql.arch.regs.x0
    if out:
        ql.mem.write(out, (1).to_bytes(4, "little"))
    return TEE_SUCCESS


def sys_wait(ql: Qiling, emu):
    return TEE_SUCCESS


def sys_get_time(ql: Qiling, emu):
    # _utee_get_time(unsigned long cat, TEE_Time *time)
    # TEE_Time { uint32_t seconds; uint32_t millis; }
    time_ptr = ql.arch.regs.x1
    if time_ptr:
        ql.mem.write(time_ptr, (1764773457).to_bytes(4, "little"))
        ql.mem.write(time_ptr + 4, (0).to_bytes(4, "little"))
        emu.writeback_shm(time_ptr, 8)
    return TEE_SUCCESS


def sys_set_ta_time(ql: Qiling, emu):
    return TEE_SUCCESS


def sys_check_access_rights(ql: Qiling, emu):
    # _utee_check_access_rights(uint32_t flags, const void *buf, size_t len)
    from unicorn import UC_PROT_READ, UC_PROT_WRITE

    flags = ql.arch.regs.x0
    buffer = ql.arch.regs.x1
    size = ql.arch.regs.x2
    found = None
    for m in ql.mem.map_info:
        if buffer >= m[0] and buffer + size <= m[1]:
            found = m
            break
    if found is None:
        return TEE_ERROR_ACCESS_DENIED
    if not (flags & TEE_MEMORY_ACCESS_ANY_OWNER) and "shared" in found[3]:
        return TEE_ERROR_ACCESS_DENIED
    if (flags & TEE_MEMORY_ACCESS_READ) and not (found[2] & UC_PROT_READ):
        return TEE_ERROR_ACCESS_DENIED
    if (flags & TEE_MEMORY_ACCESS_WRITE) and not (found[2] & UC_PROT_WRITE):
        return TEE_ERROR_ACCESS_DENIED
    return TEE_SUCCESS


def sys_random(ql: Qiling, emu):
    # _utee_cryp_random_number_generate(void *buf, size_t blen)
    buf = ql.arch.regs.x0
    blen = ql.arch.regs.x1
    if buf and blen:
        ql.mem.write(buf, b"A" * blen)
        emu.writeback_shm(buf, blen)
    return TEE_SUCCESS


def sys_get_property(ql: Qiling, emu):
    # _utee_get_property(unsigned long prop_set, unsigned long index,
    #                    void *name, uint32_t *name_len,
    #                    void *buf, uint32_t *blen, uint32_t *prop_type)
    # Not generally implemented: report the property as absent so the TA falls
    # back to its defaults. Logged for visibility.
    ql.log.info(f"[optee] get_property prop_set={ql.arch.regs.x0:#x} "
                f"index={ql.arch.regs.x1}")
    return TEE_ERROR_ITEM_NOT_FOUND


def sys_get_property_name_to_index(ql: Qiling, emu):
    return TEE_ERROR_ITEM_NOT_FOUND


# ---------------------------------------------------------------------------
# SCN -> handler table. RETURN(0) and PANIC(2) are handled in the dispatcher.
# ---------------------------------------------------------------------------
SYSCALLS = {
    scn.TEE_SCN_LOG: sys_log,
    scn.TEE_SCN_GET_PROPERTY: sys_get_property,
    scn.TEE_SCN_GET_PROPERTY_NAME_TO_INDEX: sys_get_property_name_to_index,
    scn.TEE_SCN_CHECK_ACCESS_RIGHTS: sys_check_access_rights,
    scn.TEE_SCN_GET_CANCELLATION_FLAG: sys_get_cancellation_flag,
    scn.TEE_SCN_UNMASK_CANCELLATION: sys_unmask_cancellation,
    scn.TEE_SCN_MASK_CANCELLATION: sys_mask_cancellation,
    scn.TEE_SCN_WAIT: sys_wait,
    scn.TEE_SCN_GET_TIME: sys_get_time,
    scn.TEE_SCN_SET_TA_TIME: sys_set_ta_time,
    scn.TEE_SCN_CRYP_RANDOM_NUMBER_GENERATE: sys_random,
}
