# AUTO-GENERATED generic mutational fuzz harness for SEMeSE (53454d655345).
from .params import *
from qiling import Qiling
import struct

GATE_PTYPES = 0x65
CMDS = [42,43,44,103,150,154,201,203,300,303,311,312,314,315,316]
SIZE_CHOICES = [0,1,4,8,16,64,0x100,0x400,0x1000,0x1680c]        # includes the TA's documented exact memref sizes
PUT_CMD_IN_BODY = True   # also write cmd as first u32 of params[0]
MAXBUF = 0x16810


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    sel = input[1]
    if (sel & 0xE0) == 0xE0:
        ptypes = struct.unpack_from('<H', input, 4)[0]
    else:
        ptypes = GATE_PTYPES
    # per-param size selectors
    szsel = input[2:6].ljust(4, b'\x00')
    body = input[6:]
    off = 0
    command_params = []
    for i in range(4):
        pt = (ptypes >> (4 * i)) & 0xF
        if pt in (1, 2, 3):
            a = int.from_bytes(body[off:off+4].ljust(4, b'\x00'), 'little'); off += 4
            b = int.from_bytes(body[off:off+4].ljust(4, b'\x00'), 'little'); off += 4
            command_params.append(ValueParam(a, b))
        elif pt in (4, 5, 6, 7):
            size = min(SIZE_CHOICES[szsel[i] % len(SIZE_CHOICES)], MAXBUF)
            if pt == 5:  # output only
                buf = b'\x00' * size
            else:
                chunk = body[off:off+size]; off += len(chunk)
                buf = bytearray(chunk.ljust(size, b'\x00'))
                if PUT_CMD_IN_BODY and i == 0 and size >= 4:
                    buf[0:4] = struct.pack('<I', cmd & 0xFFFFFFFF)
                buf = bytes(buf)
            command_params.append(MemRefParam(buf, size))
        else:
            command_params.append(NoneParam())
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
