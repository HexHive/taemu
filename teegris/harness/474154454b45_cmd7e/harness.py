# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"474154454b45 custom harness!!!! Placing input: {input}")

    if len(input) < 0x3A:
        return False

    command_params = []
    command_params.append(MemRefParam(bytes(0x419), 0x419))
    command_params.append(MemRefParam(input[:0x3A], 0x3A))
    command_params.append(MemRefParam(bytes(0x419), 0x419))
    command_params.append(NoneParam())
    ptypes = 0x557
    setup_fuzz(
        ql, 0x7E, ptypes, command_params, input
    )  # assume the session is already set

    return True
