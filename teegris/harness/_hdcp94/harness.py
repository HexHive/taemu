from .params import *
from qiling import Qiling

# Minimal tuned harness for HDCP cmd 0x94 (TZ_HDCP2_DEC_HK23): a large request
# (handler needs >= 0x384) and a deliberately small response buffer, so the
# handler's unchecked 880-byte write overflows it -> param redzone -> CRASH_PC.
def place_input_callback(ql: Qiling, input: bytes, _: int):
    command_params = [
        MemRefParam(bytes(0x400), 0x400),   # params[0] = req  (>= 0x384)
        MemRefParam(bytes(0x10),  0x10),    # params[1] = resp (small -> OOB)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, 0x94, 0x77, command_params)  # both memref INOUT
    return True
