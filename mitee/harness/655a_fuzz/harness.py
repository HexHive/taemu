#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"655a custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    print(hex(ql.arch.regs.sp))
    ql.arch.regs.sp -= 0x1000
    command_params = []
    command_params.append(MemRefParam(input, len(input)))
    command_params.append(ValueParam(0x10, 0x10))
    command_params.append(MemRefParam(bytes(0x1000),0x1000))
    command_params.append(ValueParam(0x10, 0x10))
    ptypes= 0x2615
    ret, params_mem = setup_params_fuzz(ql, 0, ptypes, command_params) # assume the session is already set
    return True
