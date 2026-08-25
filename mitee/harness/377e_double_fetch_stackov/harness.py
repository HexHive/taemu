from qiling import Qiling
from .params import *
from pwn import *
import hashlib


def generate_ptypes(p0, p1, p2, p3):
    return (p0) | (p1 << 4) | (p2 << 8) | (p3 << 12)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"377e_double_fetch_stackov custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    ptypes = 0
    command_params = []
    command_params.append(ValueParam(4, 4))
    possible_shared_input = MemRefParam(input, len(input))
    possible_shared_input.is_shared = True
    command_params.append(possible_shared_input)
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = generate_ptypes(3, 5, 0, 0)
    setup_fuzz(ql, 0x100B, ptypes, command_params, input)
    return True
