# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"Custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    cmds = list(range(0x9000, 0x9006)) + [0x8001, 0x8004] + list(range(0x9100, 0x9106)) + [0x9201]
    cmd = cmds[input[0] % len(cmds)]
    data = input
    command_params = []
    command_params.append(MemRefParam(data + (0x1000-len(data))*b"\x00", 0x1000))
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(ql, cmd, ptypes, command_params, input)
    return True
