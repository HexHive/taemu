# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"3d08 custom harness!!!! Placing input: {input}")

    cmd = 0x1001 
    command_params = []
    input = p32(1) + p32(0x600) + input
    output = p32(0) + p32(0x600)
    command_params.append(
        MemRefParam(input + (0x608 - len(input)) * b"\x00", 0x608)
    )
    command_params.append(MemRefParam(input + (0x608 - len(input)) * b"\x00", 0x608))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
