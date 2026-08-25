#from params import *
from .params import *
from pwn import *
from qiling import Qiling

# fido_ctap (Goodix CTAP2) fuzz harness. Drives the GP cmd id across the vendor
# command space (incl. 0x50 = passkey_load, the S16-F9 stack-OOB-write target)
# and feeds the CBOR/passkey payload as the slot0 MEMREF. paramTypes pinned 0x65
# (fido pins it; a mismatch just returns BAD_PARAMETERS). 1st input byte selects
# the cmd; the rest is the attacker payload (the CBOR map whose unclamped
# `listSize` drives the F9 overflow). Param redzones (asan) on under fuzz.
CMDS = [0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x20, 0x30, 0x40,
        0x50,            # passkey_load (F9)
        0x51, 0x52, 0x60, 0x70, 0x80, 0x100, 0x200]

def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"14b0 fido harness; input={input[:16]!r} len={len(input)}")
    if len(input) < 8:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    payload = input[1:]
    command_params = []
    command_params.append(MemRefParam(payload + b"\x00" * (0x608 - len(payload)) if len(payload) < 0x608 else payload, max(len(payload), 0x608)))
    command_params.append(MemRefParam(bytes(0x608), 0x608))
    command_params.append(NoneParam())
    command_params.append(NoneParam())
    setup_params_fuzz(ql, cmd, 0x65, command_params)
    return True
