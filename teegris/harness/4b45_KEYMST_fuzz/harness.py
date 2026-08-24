# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"keymst custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    data = input
    data = p32(len(input)-8) + data
    command_params = []
    command_params.append(MemRefParam(data, len(data)))
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, 1, ptypes, command_params, input
    )  # assume the session is already set

    return True
