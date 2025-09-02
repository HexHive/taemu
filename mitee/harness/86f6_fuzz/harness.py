#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"86f6 custom harness!!!! Placing input: {input}")

	if len(input) < 8:
		return False
	
	cmds = [0, 0x102, 0x300, 0x2114, 0x8001, 0x8003, 0xb000, 0xb001, 0xff01, 0xff02, 0xff03, 0xff04, 0xff05, 0xff06, 0xff07, 0xf002, 0xf600]
	cmd = cmds[input[0] % len(cmds)]
	command_params = []
	command_params.append(MemRefParam(input[1:] + b"\x00"*(0x1008- len(input)),0x1008))
	command_params.append(MemRefParam(bytes(0x1000),0x1008))
	command_params.append(NoneParam())
	command_params.append(NoneParam())
	ptypes= 0x65
	ret, params_mem = setup_params_fuzz(ql, cmd, ptypes, command_params) # assume the session is already set

	return True
