#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === widevine_real / OEMCrypto v19.2.0 (e97c270e) structure-aware harness =====
# (Wave-2 F4) Replaces the broken skeleton that put the fuzz input in param1
# (output) with param0 all-zero -> cmd_id=0 -> dispatcher default -> 2.53% cov.
#
# REAL entry gate (TA_InvokeCommandEntryPoint @0x54078, re-derived from binary):
#   w1 (GP commandID) == 0          (cbnz w1 -> fail @0x540b4)
#   w2 (paramTypes)   == 0x177      (cmp w2,#0x177; b.ne @0x540b8)
#       0x177 nibbles -> p0=MEMREF_INOUT(7), p1=MEMREF_INOUT(7),
#                        p2=VALUE_INPUT(1), p3=NONE(0)
#   param0.size (= [params+8]) <= 0x8000       (cmp w8,#0x8000; b.hi @0x54114)
#   param2.value.a (= [params+0x20], payload_len) <= param0.size  (b.ls @0x5411c)
#   Then ODK_Message_Init(state, param0.buf, param0.size); bind payload_len;
#   OPK_DispatchMessage(state, param0.buf) @0x6a060.
#
# => The OEMCrypto request frame lives in PARAM0. param1 = output buffer.
#    param2.value.a = payload_len (we set it to len(frame)).
#
# WIRE FORMAT (GEN_tee_serializer.c, BIG-ENDIAN fixed-layout):
#   frame = [u8 tag=0x07][BE u32 cmd_id][ per-command struct fields, BE ]
#   tag must be 0x07 (top message-struct type, checked @0x7bb84).
#   Every variable field is length-prefixed and bounded vs payload_len, so the
#   framework layer is fully bounds-checked; the fuzzer's value is to drive the
#   per-command IMPL parsers (CENC subsample math, license-substring offsets).
#
# Strategy: build frame = tag(0x07) + BE32(cmd) + body. The fuzz `input`
#   supplies BOTH the cmd id (byte 0, mapped onto the 92 implemented cmds) and
#   the body, so AFL explores the dispatcher + all unpacker bodies. A fixed cmd
#   can be pinned via E97C_CMD for targeted replay.

PTYPES = 0x177
GP_CMD = 0          # GP commandID must be 0
OUTSZ  = 0x2000     # output buffer (param1), redzoned

# Implemented OEMCrypto v19 cmd ids (from RE doc command table) -- AFL byte 0 is
# mapped onto this list so every fuzz iter hits a *real* dispatch arm.
IMPL_CMDS = [
    1,2,3,4,5,7,8,9,10,14,22,29,32,36,37,38,39,41,44,45,46,49,52,54,61,62,63,64,
    65,66,67,68,71,78,84,85,86,89,93,94,96,97,98,101,103,104,107,108,109,110,111,
    112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,
    131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,
    150,151,154,
]

def _frame(cmd, body):
    # tag 0x07 + big-endian u32 cmd id + body
    return b"\x07" + struct.pack(">I", cmd & 0xFFFFFFFF) + body

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 1:
        return False

    pin = os.environ.get("E97C_CMD")
    if pin is not None:
        cmd = int(pin, 0)
        body = input
    else:
        cmd = IMPL_CMDS[input[0] % len(IMPL_CMDS)]
        body = input[1:]

    frame = _frame(cmd, body)
    if len(frame) > 0x8000:
        frame = frame[:0x8000]
    payload_len = len(frame)

    command_params = [
        MemRefParam(frame, len(frame)),       # param0: OEMCrypto request (parsed)
        MemRefParam(bytes(OUTSZ), OUTSZ),     # param1: output buffer (redzoned)
        ValueParam(payload_len, 0),           # param2.value.a = payload_len
        NoneParam(),
    ]
    setup_fuzz(ql, GP_CMD, PTYPES, command_params, input)
    return True
