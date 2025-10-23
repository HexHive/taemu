# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"59a4 custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmds = [
        0xF001,
        0xF002,
        0xF003,
        0xF004,
        0xF005,
        0xF006,
        0xF007,
        0xF008,
        0xF010,
        0xF011,
    ]
    cmd = cmds[input[0] % len(cmds)]
    command_params = []
    command_params.append(
        MemRefParam(input[1:] + b"\x00" * (0x40C - len(input[1:])), 0x40C)
    )
    command_params.append(MemRefParam(bytes(0x408), 0x408))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    ret, params_mem = setup_params_fuzz(
        ql, cmd, ptypes, command_params
    )  # assume the session is already set
    return True
