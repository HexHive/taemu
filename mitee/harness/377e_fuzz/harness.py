from qiling import Qiling
from .params import *
from pwn import *
import hashlib


def generate_ptypes(p0, p1, p2, p3):
    return (p0) | (p1 << 4) | (p2 << 8) | (p3 << 12)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"377e_double_fetch_stackov custom harness!!!! Placing input: {input}")

    # TODO: check the input size? whether should be at least 0x80 bytes?
    if len(input) < 2:
        return False

    cmd = input[0] 
    data = input[1:]
    cmd2ptypes = {
        0x100A: 0x53,
        0x100B: 0x53,
        0x100C: 0x6553,
    }
    if cmd not in cmd2ptypes:
        return False
    ptypes = cmd2ptypes[cmd]
    command_params = []
    if cmd == 0x100B:
        command_params.append(ValueParam(4, 4))
        possible_shared_input = MemRefParam(data, len(data))
        possible_shared_input.is_shared = True
        command_params.append(possible_shared_input)
        command_params.append(NoneParam())
        command_params.append(NoneParam())
    elif cmd == 0x100C:
        command_params.append(ValueParam(len(data), len(data)))
        command_params.append(MemRefParam(data, len(data)))
        command_params.append(MemRefParam(bytes(40), 40))
        command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    elif cmd == 0x100A:
        command_params.append(ValueParam(len(data), len(data)))
        command_params.append(MemRefParam(data, len(data)))
        command_params.append(NoneParam())
        command_params.append(NoneParam())

    setup_fuzz(ql, cmd, ptypes, command_params, input)
    return True
