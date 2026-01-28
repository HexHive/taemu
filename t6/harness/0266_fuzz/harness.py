#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"0266 custom harness!!!! Placing input: {input}")

	if len(input) < 0x80:
		return False

	os.system(f'rm -rf ./emulate/files/1')
	command_params = []
	command_params.append(ValueParam(1,1))
	command_params.append(ValueParam(1,1))
	command_params.append(MemRefParam(input[:0x7f],0x7f))
	command_params.append(MemRefParam(input[0x7f:],len(input[0x7f:])))
	ptypes= 0x5733
	ret, params_mem = setup_params_fuzz(ql, 1, ptypes, command_params) # assume the session is already set

	return True
