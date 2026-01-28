#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"9811 custom harness!!!! Placing input: {input}")

	if len(input) < 8:
		return False

	cmd = input[0]
	command_params = []
	command_params.append(MemRefParam(input[1:],len(input)-1))
	command_params.append(MemRefParam(bytes(0x1000),0x1000))
	command_params.append(NoneParam())
	command_params.append(NoneParam())
	ptypes= 0x65
	ret, params_mem = setup_params_fuzz(ql, cmd, ptypes, command_params) # assume the session is already set

	return True
