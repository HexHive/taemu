# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"534b4d custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmds = list(range(0x200, 0x206))
    cmd = cmds[input[0] % len(cmds)]
    data = input[1:]
    # input = p64(input[0] + (len(input)-8-1)<<0x20) + input[1:]
    command_params = []
    command_params.append(MemRefParam(data + (0x880 - len(data)) * b"\x00", 0x880))
    command_params.append(MemRefParam(bytes(0x880), 0x880))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x67
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set

    return True
