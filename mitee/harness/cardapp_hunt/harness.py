#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === NEW-BUG hunt: cardapp/SOTER structure-aware command fuzz ==========
# lapis cardapp 86f623f6-a299-4dfd-b560ffd3e5a62c29. Dispatcher @0x25a78:
#   paramTypes==0x65. cmds with (id & 0xff00)==0xff00 are the internal/peer-ACL
#   path (incl. F5 root_sign 0xff01 -- gated, not our target). The REE-facing
#   commands are the lower ids; they parse the param0 IN memref. We frame IN as a
#   length-prefixed SOTER-style blob and sweep the REE-facing cmd space + body
#   lengths/contents to hit the ECC sign/verify/provision parsers.

PTYPES = 0x65
INSZ = 0x1000
OUTSZ = 0x1000
# REE-facing cmd ids to exercise (avoid the 0xff00 peer range which is ACL-gated)
CMDS = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x100, 0x101, 0x102, 0x103,
        0x104, 0x105, 0x200, 0x300]

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 3:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    body = input[2:]
    # length-prefixed blob: [u32 blob_len][blob]; many SOTER cmds read a u32 len
    # then copy/parse that many bytes. Let AFL drive blob_len (clamped to fit) +
    # the bytes, plus a few extra u32 sub-length fields it can mutate.
    blob_len = (input[1] | (len(body) << 8)) & 0xFFFF
    buf = struct.pack("<I", blob_len) + body
    buf = buf[:INSZ].ljust(INSZ, b"\x00")
    command_params = [
        MemRefParam(buf, INSZ),
        MemRefParam(bytes(OUTSZ), OUTSZ),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)
    return True
