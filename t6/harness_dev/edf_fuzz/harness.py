# from params import *
from .params import *
from pwn import *
from qiling import Qiling

def init_fuzz(emu, sid):
    print("init_fuzz!!")
    command_params = []
    data = b"A" * 0x100
    command_params.append(MemRefParam(data,len(data)))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    command_params.append(NoneParam())	
    emu.InvokeCommand(sid, 1+200, 0x7, command_params)
    data2 = b"B" * 0x100
    command_params[0] = MemRefParam(data2,len(data2))
    emu.InvokeCommand(sid, 2+200, 0x7, command_params)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"edfc custom harness!!!! Placing input: {input}")
    
    cmds = [a+200 for a in range(0, 0x37)]
    cmd = cmds[input[0] % len(cmds)]
    data = input[1:]
    command_params = []
    command_params.append(MemRefParam(data, len(data)))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 7
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set

    return True
