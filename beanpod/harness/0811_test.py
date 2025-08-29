#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"Custom harness!!!! Placing input: {input}")

	if len(input) < 4:
		return False

	ptypes = 0
	command_params = []
	command_params.append(MemRefParam(input,len(input)))
	command_params.append(MemRefParam(0x100*b"\x00",0x100))
	command_params.append(ValueParam(4,4))
	command_params.append(NoneParam())
	ptypes= 0x275
	ret, params_mem = setup_params_fuzz(ql, 1, ptypes, command_params) # assume the session is already set
	if ret != TEE_SUCCESS:
		return False

	return True
