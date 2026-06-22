#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === hw_proxy (9811) MULTI-COMMAND stateful harness ========================
# Run with TAEMU_MULTI_CMD=N: AFL input is framed into N records [u16 len][bytes];
# each record is one InvokeCommand in ONE session (heap/session state persists).
# This chains the provisioning/presentation state machine to reach the deep
# AOSP libeic parsers that single-shot can't (initialize -> setReaderKey ->
# validateRequest -> retrieveEntry...). asan param-redzones still catch any OOB.
#
# Per record: byte0 = cmd selector (mapped to an even cmd 0..0x48), rest = op body.
# paramTypes pinned 0x65 (the only accepted shape). param0=INPUT(body),
# param1=OUTPUT(0x1000).

PTYPES = 0x65
OUTSZ = 0x1000
EVEN_CMDS = list(range(0, 0x49, 2))

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 1:
        # empty record: issue a no-op-ish cmd so the session keeps going
        cmd = 20  # PresentInitialize
        body = b""
    else:
        cmd = EVEN_CMDS[input[0] % len(EVEN_CMDS)]
        body = input[1:]
    print(f"[9811-mc] cmd={cmd} ptypes=0x65 bodylen={len(body):#x}")
    command_params = [
        MemRefParam(body, len(body)),
        MemRefParam(bytes(OUTSZ), OUTSZ),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)
    return True
