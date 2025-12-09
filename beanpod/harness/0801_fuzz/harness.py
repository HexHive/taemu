# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"Custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False
    
    cmds = [0, 3, 5]
    cmd = cmds[input[0] % len(cmds)]
    data = input[1:]
    command_params = []
    if cmd in (0,5):
        if len(data) < 0x40:
            data = data + 0x40 * b"\x00"
        command_params.append(MemRefParam(data, len(data)))
        command_params.append(MemRefParam(bytes(0x1000), 0x1000))
        command_params.append(NoneParam())
        command_params.append(NoneParam())
        ptypes = 0x65
    if cmd == 3:
        command_params.append(MemRefParam(data, len(data)))
        command_params.append(NoneParam())
        command_params.append(NoneParam())
        command_params.append(NoneParam())
        ptypes = 0x6
    setup_fuzz(ql, cmd, ptypes, command_params, input)
    return True
