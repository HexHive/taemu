#from params import *
from .params import *
from pwn import *
from qiling import Qiling

"""
def init_fuzz(emu, sid):
	print("init_fuzz!!")
	command_params = []
	data = p32(0x1007) + p32(0x33f) + b"\x00"*0x33f
	command_params.append(MemRefParam(data,len(data)))
	command_params.append(ValueParam(123,123))
	command_params.append(NoneParam())
	command_params.append(NoneParam())	
	emu.InvokeCommand(sid, 1, 0x9999, command_params)
"""

def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"face custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    cmds = [0, 1, 2]
    cmd = cmds[input[0] % len(cmds)]
    input = input[1:]
    command_params = []
    if cmd == 0:
        command_params.append(MemRefParam(input[1:],len(input[1:])))
        command_params.append(ValueParam(input[0],input[0]))
        command_params.append(NoneParam())
        command_params.append(NoneParam())
        ptypes= 0x51
    elif cmd == 1:
        command_params.append(MemRefParam(input[1:],len(input[1:])))
        command_params.append(MemRefParam(bytes(0x1000),0x1000))
        command_params.append(MemRefParam(bytes(0x1000),0x1000))
        command_params.append(MemRefParam(bytes(0x1000),0x1000))
        ptypes = 0x6555
    elif cmd == 2:
        command_params.append(MemRefParam(input[1:],len(input[1:])))
        command_params.append(MemRefParam(bytes(0x1000),0x1000))
        command_params.append(NoneParam())
        command_params.append(NoneParam())
        ptypes = 0x65
    else:
        return False
    ret, params_mem = setup_params_fuzz(ql, cmd, ptypes, command_params) # assume the session is already set

    return True
