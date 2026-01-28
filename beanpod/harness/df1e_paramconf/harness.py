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
	command_params.append(MemRefParam(p32(0x1004)+ input,len(input)+4))
	command_params.append(ValueParam(0xdeadbeef,8))
	command_params.append(NoneParam())
	command_params.append(NoneParam())
	ptypes= 0x9999
	ret, params_mem = setup_params_fuzz(ql, 1, ptypes, command_params) # assume the session is already set
	if ret != TEE_SUCCESS:
		return False

	return True
