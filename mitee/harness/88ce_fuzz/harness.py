# === F7 / 88ce8e6b ifaa — GlobalConfusion probe + IFAA-message structure drive ====
# Staged klee build (Invoke @0x24ae8). Open returns TEE_SUCCESS unconditionally.
#
# ENTRY GATE (re-derived from staged .ta):
#   cmp w19,#0x65 (paramTypes MUST==0x65: param0=MEMREF_INPUT, param1=MEMREF_OUTPUT)
#   [x20+8]  (params[0].size)  MUST == 0x100C  (4108)
#   [x20+0x18](params[1].size) MUST == 0x1008  (4104)
#   ldr x21,[x20]; ldr w7,[x21+8]; cmp w7,#0x1000; b.ls   -> *(u32*)(buf+8) MUST <= 0x1000
#
# IFAA message (params[0].buffer):
#   +0  u32 tag        (MUST == 1 for the F00x/0x100x dispatch; else other path)
#   +4  u32 command    (masked; -0xF001 -> jump table F001..F006; ==0x1000/0x1001 special)
#   +8  u32 in_len     (attacker length, bounded <= 0x1000 at the gate)
#   +0xC payload[...]
#
# cmd map (jump table @0xae58, base 0x24c94):
#   0xF001->0x292a0  0xF002->0x29358  0xF003->0x29688(uses in_len@+8, payload@+0xC)
#   0xF004->0x29ab8  0xF005->0x28f98  0xF006->0x29??  0x1000->0x28328  0x1001->0x24d90
#
# MODE (env TAEMU_F7_MODE):
#   gc      : GlobalConfusion probe (flip memref slots to VALUE poison)
#   ifaa    : valid IFAA frame, AFL mutates command + in_len + payload (structure-aware)
#   cmd     : pin a single cmd (env F7_IFCMD), vary in_len (env F7_INLEN) + payload
from .params import *
from qiling import Qiling
import struct, os

MODE   = os.environ.get("TAEMU_F7_MODE", "ifaa")
POISON = int(os.environ.get("F7_POISON", "0x4142434445"), 0)
FLIP   = os.environ.get("F7_FLIP", "0,1")
FLIP_SLOTS = [int(x) for x in FLIP.split(",") if x != ""]
GC_CMD = int(os.environ.get("F7_CMD", "0xF003"), 0)

IFCMD  = int(os.environ.get("F7_IFCMD", "0xF003"), 0)
INLEN  = int(os.environ.get("F7_INLEN", "0x1000"), 0) & 0xFFFFFFFF
TAG    = int(os.environ.get("F7_TAG", "1"), 0) & 0xFFFFFFFF

P0SZ = 0x100C
P1SZ = 0x1008


def _frame(tag, cmd, in_len, payload):
    hdr = struct.pack("<III", tag, cmd, in_len)
    buf = hdr + payload
    return buf[:P0SZ].ljust(P0SZ, b"\x00")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if MODE == "gc":
        pt = 0
        for i in FLIP_SLOTS:
            pt |= (0x1 << (4 * i))
        params = [NoneParam(), NoneParam(), NoneParam(), NoneParam()]
        lo, hi = POISON & 0xffffffff, (POISON >> 32) & 0xffffffff
        for i in FLIP_SLOTS:
            params[i] = ValueParam(lo, hi)
        print(f"[F7 88ce GC] cmd={GC_CMD:#x} pt={pt:#06x} POISON={POISON:#x} FLIP={FLIP_SLOTS}")
        setup_fuzz(ql, GC_CMD, pt, params, input)
        return True

    if MODE == "cmd":
        cmd = IFCMD
        in_len = INLEN
        # payload from input (after we reserve nothing — full input is payload bytes)
        payload = input if input else b"\x41" * 0x40
        buf = _frame(TAG, cmd, in_len, payload)
        print(f"[F7 88ce cmd] cmd={cmd:#x} in_len={in_len:#x} tag={TAG} paylen={len(payload):#x}")
        params = [MemRefParam(buf, P0SZ), MemRefParam(bytes(P1SZ), P1SZ), NoneParam(), NoneParam()]
        setup_fuzz(ql, 0, 0x65, params, input)   # GP cmd id is ignored; dispatch is in-band
        return True

    # ifaa: AFL-driven structure-aware. input layout we impose:
    #   input[0:4] = command (LE)   input[4:8] = in_len (LE)   input[8:] = payload
    if MODE == "ifaa":
        if len(input) >= 8:
            cmd = struct.unpack_from("<I", input, 0)[0]
            in_len = struct.unpack_from("<I", input, 4)[0] & 0xFFFFFFFF
            payload = input[8:]
            # keep cmd in the dispatchable set most of the time (bias AFL)
            if (cmd & 0xFFFF) not in (0xF001, 0xF002, 0xF003, 0xF004, 0xF005, 0xF006, 0x1000, 0x1001):
                cmd = 0xF001 + (cmd % 6)
        else:
            cmd, in_len, payload = 0xF003, 0x1000, b"\x41" * 0x80
        # in_len must be <= 0x1000 to pass the gate (else early return, no parse)
        in_len &= 0xFFF
        buf = _frame(TAG, cmd, in_len, payload)
        print(f"[F7 88ce ifaa] cmd={cmd:#x} in_len={in_len:#x} paylen={len(payload):#x}")
        params = [MemRefParam(buf, P0SZ), MemRefParam(bytes(P1SZ), P1SZ), NoneParam(), NoneParam()]
        setup_fuzz(ql, 0, 0x65, params, input)
        return True

    print("[F7 88ce] unknown MODE")
    setup_params_fuzz(ql, 0, 0, [NoneParam()] * 4)
    return True
