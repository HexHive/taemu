# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"88ce custom harness!!!! Placing input: {input}")

    cmds = [0xf001, 0xf002, 0xf003, 0xf004, 0xf005, 0xf006, 0x1001, 0x1000]
    cmd = cmds[input[0] % len(cmds)]
    command_params = []
    input = p32(1) + p32(cmd) + input[1:]
    command_params.append(
        MemRefParam(input + (0x100c - len(input)) * b"\x00", 0x100c)
    )
    command_params.append(MemRefParam(0x1008*b"\x00", 0x1008))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
