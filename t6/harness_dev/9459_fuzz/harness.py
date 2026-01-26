# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def init_fuzz(emu, sid):
    print("init_fuzz!!")
    command_params = []
    data = p32(0x1007) + p32(0x33F) + b"\x00" * 0x33F
    command_params.append(MemRefParam(data, len(data)))
    command_params.append(ValueParam(123, 123))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    emu.InvokeCommand(sid, 1, 0x9999, command_params)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"9459 custom harness!!!! Placing input: {input}")

    if len(input) < 4:
        return False

    cmds = [0x1000, 0x1005, 0x1006]
    cmds += list(range(0x101b, 0x1027)) + list(range(0x2000, 0x2008))
    cmd = cmds[input[0] % len(cmds)]
    data = p32(cmd) + input[1:]
    
    # cmd = cmds[input[0] % len(cmds)]
    # data = (0x1026).to_bytes(4, "little") + input
    # data = (0x1018).to_bytes(4, "little") + 12*b"\x00" + p32(0x8395) + input
    command_params = []
    command_params.append(MemRefParam(data, len(data)))
    command_params.append(ValueParam(123, 123))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    ptypes = 0x9999
    setup_fuzz(
        ql, cmd, ptypes, command_params, input
    )  # assume the session is already set

    return True
