# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"8aaa custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False

    cmd_ids = [
        0x9001,
        0x9002,
        0x9003,
        0x9004,
        0x9005,
        0x9006,
        0x9007,
        0x8001,
        0x8004,
        0x9101,
        0x9102,
        0x9103,
        0x9201,
    ]
    cmd = cmd_ids[input[0] % len(cmd_ids)]
    command_params = []
    command_params.append(
        MemRefParam(input[1:] + b"\x00" * (0x1000 - len(input[1:])), 0x1000)
    )
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
