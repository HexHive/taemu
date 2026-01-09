# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"rust eth custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    command_params = []
    command_params.append(MemRefParam(input, len(input)))
    command_params.append(ValueParam(4,4))
    command_params.append(MemRefParam(bytes(0x608), 0x608))
    command_params.append(NoneParam())
    ptypes = 0x737
    setup_fuzz(
        ql, 0, ptypes, command_params, input
    )  # assume the session is already set
    return True
