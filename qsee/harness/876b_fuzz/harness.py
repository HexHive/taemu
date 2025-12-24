# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"qsee custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False
    cmds = [0x32c9, 0x32ca, 0x32cb, 0x32cc, 0x32cd]
    cmd = cmds[input[0] % len(cmds)]
    data = input[1:]
    command_params = []
    command_params.append(MemRefParam(input[1:], len(input[1:])))
    command_params.append(ValueParam(0,0))
    command_params.append(ValueParam(0,0))
    command_params.append(ValueParam(0,0))
    ptypes =0x2227 
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
