# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"00575644524d custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmd = input[0]
    data = input[1:]
    command_params = []
    command_params.append(MemRefParam(data + b"\x00" * (0x500C - len(data)), 0x500C))
    command_params.append(MemRefParam(bytes(0x500C), 0x500C))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set

    return True
