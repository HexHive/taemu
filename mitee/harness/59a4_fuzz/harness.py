# from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === keybag / MKEYBAG (59a4867c) structure-aware harness (F3, Wave 2) =========
# Staged .ta build: dispatcher @0x201B0 (entry 0x20000). REAL gate (re-derived by
# capstone, the section-stripped .ta — NOT the RE doc's .elf offsets):
#   paramTypes == 0x65            (memref-IN + memref-OUT)         cmp w21,#0x65
#   params[0].size == 0x40C (2060)                                 ldr w7,[x20,#8]
#   params[1].size == 0x408 (2056)                                 ldr w8,[x20,#0x18]
#   params[0].buf[0] (version tag) == 1                            ldr w5,[x23]; cmp #1
# then jump table cmd-0xF001..0xF011.
#
# Handler ABI (from the case blocks):
#   F001 ClientTicket_prepare: worker(in=buf+0xC, in_len=*(u32*)(buf+8), ...) @0x20bd0
#        -> malloc(440) + memcpy(440) FIXED size (in_len only zero-checked) => outer
#        copy is length-SAFE (buf+0xC+440=452 < 0x40C). Interior parse at fixed offs.
#   F002 import_MasterKey: memcpy FIXED #0x172 (370) from buf+0x10 => length-SAFE.
#   F010/F011 KEYBAG_MK_is_{en,de}crypt: worker @0x27100/0x27578 takes (in_ptr, in_len,
#        out_ptr, &out_len). in data at in_ptr+0x14; in_len drives the GCM update.
#        ==> the one OUTER length-confusion candidate: if in_len > 0x40C-0x14 the GCM
#        update walks past the redzoned 0x40C param buffer. NO check vs param size seen.
#   F007 execute: inner op_tag dispatcher (1..6), op_tag re-encoded from a caller u32.
#
# Two modes:
#   * default (AFL): input[0] picks cmd; the rest is the body; the body's own length
#     fields are mutated by AFL. Version tag forced to 1, GP envelope kept valid.
#   * KB_CMD pinned (env): drive one cmd; KB_INLEN sets the buf+8 in_len field so the
#     F010/F011/F001 length-confusion hypothesis can be tested deterministically.

PTYPES = 0x65
P0SZ = 0x40C      # 2060
P1SZ = 0x408      # 2056

# valid external command ids (jump table covers F001..F011 = 17 entries)
CMDS = [0xF001, 0xF002, 0xF003, 0xF004, 0xF005, 0xF006, 0xF007, 0xF010, 0xF011]

PIN_CMD = os.environ.get("KB_CMD")
PIN_CMD = int(PIN_CMD, 0) if PIN_CMD else None
# in_len field placed at param0.buf+8 (F001/F010/F011 read it as the inner length).
# Default 0xFFFFFFFF to probe the in_len > param-size length-confusion on F010/F011.
PIN_INLEN = os.environ.get("KB_INLEN")
PIN_INLEN = (int(PIN_INLEN, 0) & 0xFFFFFFFF) if PIN_INLEN else None


def _frame(version, inlen, body):
    # param0 layout (0x40C):
    #   +0 : u32 version (gate == 1)
    #   +4 : u32 (cmd-specific / sub-tag for F007; unused by F001/F010 outer)
    #   +8 : u32 inner in_len  (F001/F010/F011 read this as the data length)
    #   +0xC.. : data
    buf = bytearray(P0SZ)
    struct.pack_into("<I", buf, 0, version & 0xFFFFFFFF)
    if inlen is not None:
        struct.pack_into("<I", buf, 8, inlen & 0xFFFFFFFF)
    b = body[: P0SZ - 0xC]
    buf[0xC : 0xC + len(b)] = b
    return bytes(buf)



def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False

    if PIN_CMD is not None:
        cmd = PIN_CMD
        inlen = PIN_INLEN
        body = input  # full body fuzzable
    else:
        cmd = CMDS[input[0] % len(CMDS)]
        # let AFL drive the inner in_len field too (buf+8); seed from bytes 1..5
        if len(input) >= 5:
            inlen = struct.unpack_from("<I", input, 1)[0]
        else:
            inlen = 0
        body = input[5:]

    buf = _frame(1, inlen, body)
    il = inlen if inlen is not None else -1
    print(f"[KB] cmd={cmd:#06x} ptypes=0x65 p0sz={P0SZ:#x} version=1 in_len={il:#x} "
          f"bodylen={len(body)}")

    command_params = [
        MemRefParam(buf, P0SZ),            # param0 INPUT (redzoned 0x40C)
        MemRefParam(bytes(P1SZ), P1SZ),    # param1 OUTPUT (redzoned 0x408)
        NoneParam(),
        NoneParam(),
    ]
    setup_fuzz(ql, cmd, PTYPES, command_params, input)
    return True
