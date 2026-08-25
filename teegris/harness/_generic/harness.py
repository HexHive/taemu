from .params import *
from pwn import *
from qiling import Qiling
import struct

# TA-agnostic harness: fuzz the command id (4 bytes) + param-types word (2
# bytes) + the param data, building the 4 TEE_Params to MATCH the fuzzed
# ptypes nibbles so the layout is always self-consistent. This exercises any
# TEEGRIS dispatcher (cmd routing + param-type/size validation + early
# handlers) regardless of the TA, which is enough to tell whether the TA
# *runs* under InvokeCommand (coverage grows, no emulator wall) vs. only boots.
# Not tuned to reach any one deep handler -- that needs a per-TA harness.

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    cmd = struct.unpack_from("<I", input, 0)[0]
    ptypes = struct.unpack_from("<H", input, 4)[0]
    body = input[6:]
    off = 0
    command_params = []
    for i in range(4):
        pt = (ptypes >> (4 * i)) & 0xF
        if pt in (1, 2, 3):  # value in/out/inout
            a = int.from_bytes(body[off:off + 4].ljust(4, b"\x00"), "little"); off += 4
            b = int.from_bytes(body[off:off + 4].ljust(4, b"\x00"), "little"); off += 4
            command_params.append(ValueParam(a, b))
        elif pt in (4, 5, 6, 7):  # memref in/out/inout
            size = 0x100
            chunk = body[off:off + size]; off += len(chunk)
            command_params.append(MemRefParam(chunk.ljust(size, b"\x00"), size))
        else:  # none
            command_params.append(NoneParam())
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
