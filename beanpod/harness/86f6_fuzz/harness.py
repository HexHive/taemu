# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"Custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    cmds = [0xb001, 0x2114, 0x102, 0x300, 0xff03, 0xff05, 0xff04, 0xff06, 0xff07, 0xf600, 0xff01, 0xff02, 0xf002]
    cmd = cmds[input[0] % len(cmds)]
    data = input[1:]
    command_params = []
    command_params.append(MemRefParam(data + (0x1008-len(data))*b"\x00", 0x1008))
    command_params.append(MemRefParam(bytes(0x1008), 0x1008))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x65
    setup_fuzz(ql, cmd, ptypes, command_params, input)
    return True
