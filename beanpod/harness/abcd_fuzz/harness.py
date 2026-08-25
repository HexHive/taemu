# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"Custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False
    cmds = list(range(0, 0x1d))
    cmd = cmds[input[0] % len(cmds)]
    data = input[1:]
    command_params = []
    command_params.append(MemRefParam(data + (0x23d-len(data))*b"\x00", 0x23d))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x7
    setup_fuzz(ql, cmd, ptypes, command_params, input)
    return True
