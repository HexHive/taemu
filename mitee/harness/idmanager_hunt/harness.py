#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === NEW-BUG hunt: idmanager structure-aware command fuzz ===============
# klee idmanager 8aaaf201-2460-0000-aabbccdd00000006, staged misa-style.
# Dispatcher (decompiled): paramTypes==0x65, param0(IN)+param1(OUT) sizes ~0x2008
#   (8200 bytes), protocol version must be 1. 12 cmds: 1-4 (misecids ops),
#   0x101-0x108 (googleid / attestation-ids / auth-token ops). Each parses the
#   IN memref body. We keep the GP/version envelope well-formed and mutate the
#   command id + the parsed body (offsets/lengths/version field) so the per-cmd
#   parsers are reached with varied structure -> hunt OOB/overflow beyond IDMANAGER-3.

PTYPES = 0x65
INSZ = 0x2008
OUTSZ = 0x2008
CMDS = [1, 2, 3, 4, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108]

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 4:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    body = input[1:]
    # IN frame: protocol version u32 at buf[0] MUST be 1 (gate: v9 == **a4 == 1).
    # handlers get v8 = param0.buf (NOT +0x10). The per-cmd parsers read length
    # fields from the body after the version; let AFL drive those raw.
    buf = (struct.pack("<I", 1) + body)[:INSZ].ljust(INSZ, b"\x00")
    command_params = [
        MemRefParam(buf, INSZ),            # param0 INPUT (redzoned)
        MemRefParam(bytes(OUTSZ), OUTSZ),  # param1 OUTPUT (redzoned)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)
    return True
