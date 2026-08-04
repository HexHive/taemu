# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"qsee custom harness!!!! Placing input: {input}")

    if len(input) < 8:
        return False
    cmds = [0x32c9, 0x32ca, 0x32cb, 0x32cc, 0x32cd]
    parms_nr = [8, 5, 2, 1, 2]
    idx = input[0] % len(cmds)
    cmd = cmds[idx]
    data = p32(cmd, endianness='big') + p32(10000, endiannes='little') + input[1:]
    data = p32(cmd, endian='big') + p32(10000, endian="big") + p32(parms_nr[idx], endian='big') + input[1:]
    command_params = []
    command_params.append(MemRefParam(data, len(data)))
    command_params.append(ValueParam(0,0))
    command_params.append(ValueParam(0,0))
    command_params.append(ValueParam(0,0))
    ptypes =0x2227 
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set
    return True
