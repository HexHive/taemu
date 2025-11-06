# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"Custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    ptypes = 0
    command_params = []
    command_params.append(MemRefParam(input, len(input)))
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, 1, ptypes, command_params, input
    )  # assume the session is already set
    return True
