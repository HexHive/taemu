# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"534b4d custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmds = [
        0x1B4,
        0xAB07,
        0xB810,
        0x110,
        0x111,
        0x120,
        0x130,
        0xBB19,
        0xBB20,
        0xBB21,
        0xBC23,
        0xB811,
        0xB914,
        0xBA17,
    ]
    data = b""
    data += p32(cmds[input[0] % len(cmds)])
    input = input[1:]
    data += p32(len(input) - 8)
    data += input
    # input = p64(input[0] + (len(input)-8-1)<<0x20) + input[1:]
    command_params = []
    command_params.append(MemRefParam(data, len(data)))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x7
    setup_fuzz(
        ql, 0x0, ptypes, command_params, input
    )  # assume the session is already set

    return True
