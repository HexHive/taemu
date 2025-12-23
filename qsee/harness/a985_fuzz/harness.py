# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"qsee custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmd = input[0] % 0x13
    data = input[1:]
    command_params = []
    command_params.append(MemRefParam(input[1:], len(input[1:])))
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    ptypes = 0x7777
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
