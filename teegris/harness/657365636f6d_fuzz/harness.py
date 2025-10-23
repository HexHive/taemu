# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"534b4d custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmds = [
        3,
        4,
        0x20021,
        0x20024,
        0x20025,
        0x20026,
        0x20028,
        0x20029,
        0x20030,
        0x22021,
        0x22022,
    ]
    cmd = cmds[input[0] % len(cmds)]
    input = input[1:]
    data = b""
    data += input
    # input = p64(input[0] + (len(input)-8-1)<<0x20) + input[1:]
    command_params = []
    command_params.append(MemRefParam(data + (0x1018 - len(data)) * b"\x00", 0x1018))
    command_params.append(MemRefParam(bytes(0x1018), 0x1018))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x67
    ret, params_mem = setup_params_fuzz(
        ql, cmd, ptypes, command_params
    )  # assume the session is already set

    return True
