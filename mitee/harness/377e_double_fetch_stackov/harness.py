from qiling import Qiling
from .params import *
from pwn import *


def generate_ptypes(p0, p1, p2, p3):
    return (p0) | (p1 << 4) | (p2 << 8) | (p3 << 12)


# def init_fuzz(emu, sid):
#     # TODO： what is this for?
#     print("init_fuzz!!")
#     command_params = []
#     data = b"\x41" * 0x90
#     command_params.append(ValueParam(4, 4))
#     possible_shared_input = MemRefParam(data, len(data))
#     possible_shared_input.is_shared = True
#     possible_shared_input.shm = data
#     command_params.append(possible_shared_input)
#     command_params.append(NoneParam())
#     command_params.append(NoneParam())
#     emu.InvokeCommand(sid, 0x100B, generate_ptypes(0x00000003, 0x00000005, 0x00000000, 0x00000000), command_params)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"377e_double_fetch_stackov custom harness!!!! Placing input: {input}")

    # initialize cache for this input
    seed_id = f"run:id:{hashlib.md5(input).hexdigest()}"
    ql.set_curr_key(seed_id)
    ql.set_cache(seed_id, [])

    # TODO: check the input size? whether should be at least 0x80 bytes?
    if len(input) < 4:
        return False


    ql.log.debug(
        f"377e_double_fetch_stackov custom harness, placing input: {input.hex()}, size: {len(input)}"
    )
    ptypes = 0
    command_params = []
    command_params.append(ValueParam(4, 4))
    possible_shared_input = MemRefParam(input, len(input))
    possible_shared_input.is_shared = True
    command_params.append(possible_shared_input)
    command_params.append(NoneParam())
    command_params.append(NoneParam())

    # define TEEC_NONE                   0x00000000
    # define TEEC_VALUE_INPUT            0x00000001
    # define TEEC_VALUE_OUTPUT           0x00000002
    # define TEEC_VALUE_INOUT            0x00000003
    # define TEEC_MEMREF_TEMP_INPUT      0x00000005
    # define TEEC_MEMREF_TEMP_OUTPUT     0x00000006
    # define TEEC_MEMREF_TEMP_INOUT      0x00000007
    # define TEEC_MEMREF_WHOLE           0x0000000C
    # define TEEC_MEMREF_PARTIAL_INPUT   0x0000000D
    # define TEEC_MEMREF_PARTIAL_OUTPUT  0x0000000E
    # define TEEC_MEMREF_PARTIAL_INOUT   0x0000000F

    ptypes = generate_ptypes(0x00000003, 0x00000005, 0x00000000, 0x00000000)
    ret, params_mem = setup_params_fuzz(ql, 0x100B, ptypes, command_params)
    return True
