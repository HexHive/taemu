#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"e97c custom harness!!!! Placing input: {input}")

	if len(input) < 4:
		return False

	ptypes = 0
	command_params = []
	command_params.append(MemRefParam(bytes(0x1000),0x1000))
	command_params.append(MemRefParam(input,len(input)))
	command_params.append(ValueParam(len(input),len(input)))
	command_params.append(NoneParam())
	ptypes= 0x177
	ret, params_mem = setup_params_fuzz(ql, 0, ptypes, command_params) # assume the session is already set
	if ret != TEE_SUCCESS:
		return False

	return True
