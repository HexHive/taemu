# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"86f6 custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmds = [
        0,
        0x102,
        0x300,
        0x2114,
        0x8001,
        0x8003,
        0xB000,
        0xB001,
        0xFF01,
        0xFF02,
        0xFF03,
        0xFF04,
        0xFF05,
        0xFF06,
        0xFF07,
        0xF002,
        0xF600,
    ]
    cmd = cmds[input[0] % len(cmds)]
    command_params = []
    command_params.append(
        MemRefParam(input[1:] + b"\x00" * (0x1008 - len(input)), 0x1008)
    )
    command_params.append(MemRefParam(bytes(0x1000), 0x1008))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set

    return True
