# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def init_fuzz(emu, sid):
    print(f"f130 init_fuzz!")
    command_params = []
    command_params.append(MemRefParam(bytes(0x8), 8))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x7
    emu.InvokeCommand(sid, 0x69, ptypes, command_params)
    emu.InvokeCommand(sid, 0x105, ptypes, command_params)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"f130 custom harness!!!! Placing input: {input}")

    command_params = []
    command_params.append(MemRefParam(input, len(input)))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x7
    setup_fuzz(
        ql, 0x105, ptypes, command_params, input
    )  # assume the session is already set
    return True
