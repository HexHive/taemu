from .params import *
from pwn import *
from qiling import Qiling
import os
PTYPES=0x177
def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 1: return False
    frame = input[:0x8000]
    command_params = [
        MemRefParam(bytes(0x2000),0x2000),   # param0 = OUTPUT
        MemRefParam(frame, len(frame)),      # param1 = REQUEST (parsed)
        ValueParam(len(frame),0),            # param2.value.a = payload_len
        NoneParam(),
    ]
    setup_params_fuzz(ql, 0, PTYPES, command_params)
    return True
