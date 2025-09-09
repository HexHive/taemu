#from params import *
from .params import *
from pwn import *
from qiling import Qiling

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"hdm custom harness!!!! Placing input: {input}")

	if len(input) < 8:
		return False
	
	cmds = list(range(0, 6))
	cmd = cmds[input[0] % len(cmds)]
	data = input
	data = data + (0x3300-len(data))*b"\x00"
	#data += b'\x01' + cyclic(0x21c7d-1)
	#data = bytearray(data)
	#data[1521] = 0
	#for i in range(1,8):
	#	data[1521+i] = 0
	#data[1521+4] = 4
	#data = bytes(data)
	#input = p64(input[0] + (len(input)-8-1)<<0x20) + input[1:]
	command_params = []
	command_params.append(MemRefParam(data, len(data)))
	command_params.append(MemRefParam(bytes(0x3300), 0x3300))
	command_params.append(NoneParam())
	command_params.append(NoneParam())
	ptypes= 0x67
	ret, params_mem = setup_params_fuzz(ql, cmd, ptypes, command_params) # assume the session is already set

	return True
