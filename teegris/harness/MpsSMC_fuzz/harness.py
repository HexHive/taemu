#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import base64

def place_input_callback(ql: Qiling, input: bytes, _: int):
	print(f"MpsSMC mode custom harness!!!! Placing input: {input}")

	if len(input) < 8:
		return False


	input = base64.b64encode(input)
	data = bytearray(0x4040 *b"\x00")
	for i, b in enumerate(len(input).to_bytes(4, "little")):
		data[0x10+i] = b	
	#data[0x10] =0x0
	#data[0x11] =0x40
	for i,b in enumerate(input):
		data[0x14+i] = b
	
	#data += b'\x01' + cyclic(0x21c7d-1)
	#data = bytearray(data)
	#data[1521] = 0
	#for i in range(1,8):
	#	data[1521+i] = 0
	#data[1521+4] = 4
	#data = bytes(data)
	#input = p64(input[0] + (len(input)-8-1)<<0x20) + input[1:]
	command_params = []
	command_params.append(MemRefParam(bytes(data), 0x4040))
	command_params.append(MemRefParam(bytes(0x4040), 0x4040))
	command_params.append(NoneParam())
	command_params.append(NoneParam())
	ptypes= 0x67
	ret, params_mem = setup_params_fuzz(ql, 0x15, ptypes, command_params) # assume the session is already set

	return True
