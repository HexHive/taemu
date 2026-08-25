from .params import *
from qiling import Qiling

# Drive knxgud past its PROCA prelude. The dispatcher validates
# param_types == 0x67 and both memrefs == 17472 (0x4440) before
# kg_proca_authenticate -> TEE_OpenTASession(PROCA). With the PROCA soft-pass
# modelled, the dispatcher's fall-through should reach process_cmd(cmd_id).
def place_input_callback(ql: Qiling, input: bytes, _: int):
    cmd = 0x10A  # kg_unlock (per RE; exact id may shift with the build)
    command_params = [
        MemRefParam(bytes(17472), 17472),
        MemRefParam(bytes(17472), 17472),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, 0x67, command_params)
    return True
