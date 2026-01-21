# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"e97c custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    ptypes = 0
    command_params = []
    command_params.append(ValueParam(len(input), len(input)))
    command_params.append(ValueParam(len(input), len(input)))
    command_params.append(ValueParam(len(input), len(input)))
    command_params.append(ValueParam(len(input), len(input)))
    ptypes = 0x699
    setup_fuzz(
        ql, 0x1000, ptypes, command_params, input
    )  # assume the session is already set

    return True
