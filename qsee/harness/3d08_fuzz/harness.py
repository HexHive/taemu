# from params import *
from .params import * 
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"3d08 custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmds = [0x1000, 0x1001, 0x1002, 0x1003, 1, 2, 0x2000, 0x2001, 0x2002]
    cmd = cmds[input[0] % len(cmds)]
    command_params = []
    command_params.append(
        MemRefParam(input[1:] + b"\x00" * (0x608 - len(input[1:])), 0x608)
    )
    command_params.append(MemRefParam(bytes(0x608), 0x608))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
