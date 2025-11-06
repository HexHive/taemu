# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"Custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    cmds = [1, 6]
    cmd = cmds[input[0] % len(cmds)]
    command_params = []
    if cmd == 1:
        command_params.append(MemRefParam(input[1:], len(input[1:])))
        command_params.append(MemRefParam(0x100 * b"\x00", 0x100))
        command_params.append(ValueParam(4, 4))
        command_params.append(NoneParam())
        ptypes = 0x275
    elif cmd == 6:
        command_params.append(MemRefParam(input[1:], len(input[1:])))
        command_params.append(MemRefParam(0x100 * b"\x00", 0x100))
        command_params.append(MemRefParam(0x100 * b"\x00", 0x100))
        command_params.append(NoneParam())
        ptypes = 0x765
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
