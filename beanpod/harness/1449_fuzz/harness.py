#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"Custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    cmds = [0,1,2,3,4]
    cmd = cmds[input[0] % len(cmds)]
    input = input[1:]
    command_params = []
    command_params.append(MemRefParam(input,len(input)))
    command_params.append(MemRefParam(bytes(0x1000), 0x1000))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes= 0x65
    ret, params_mem = setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
