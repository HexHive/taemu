#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"474154454b45 custom harness!!!! Placing input: {input}")

	if len(input) < 0x3a:
		return False

	command_params = []
	command_params.append(MemRefParam(bytes(0x419), 0x419))
	command_params.append(MemRefParam(input[:0x3a], 0x3a))
	command_params.append(MemRefParam(bytes(0x419), 0x419))
	command_params.append(NoneParam())
	ptypes= 0x557
	ret, params_mem = setup_params_fuzz(ql, 0x7e, ptypes, command_params) # assume the session is already set

	return True
