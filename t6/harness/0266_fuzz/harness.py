# from params import *
from .params import *
from pwn import *
from qiling import Qiling


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"0266 custom harness!!!! Placing input: {input}")

    if len(input) < 0x80:
        return False

    os.system(f"rm -rf ./emulate/files/1")
    command_params = []
    command_params.append(ValueParam(1, 1))
    command_params.append(ValueParam(1, 1))
    command_params.append(MemRefParam(input[:0x7F], 0x7F))
    command_params.append(MemRefParam(input[0x7F:], len(input[0x7F:])))
    ptypes = 0x5733
    setup_fuzz(
        ql, 1, ptypes, command_params, input
    )  # assume the session is already set

    return True
