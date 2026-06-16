# AUTO-GENERATED generic mutational fuzz harness for vltkpr (564c544b5052).
from .params import *
from qiling import Qiling
import struct

# Dispatcher RE (objdump, SFDZE1 @0x1c35c): param-types gate is ptype low nibble
# == 7 (0x1c3a8 and w8,w19,#0xf; cmp #7) AND second nibble == 6 (0x1c3b8 and
# w8,w19,#0xf0; cmp #0x60) => 0x67 (param[0]=MEMREF_IN, param[1]=MEMREF_OUT). The
# old 0x77 here made param[1] INOUT and, with SIZE_CHOICES incl. 0, frequently
# NULL -> "rsp is null" early-out before vk_authenticate_ca/vk_switcher. Use 0x67
# and force a NON-ZERO response buffer. CMDS: bias to the IN-MASK cmds (corpus
# class-2 mask 0x040780D7; the headline 0xC000C10 VERIFY_CERT is OUT-of-mask on
# this build -> -30004 before dispatch, INDEX.md). Keep 0xC000C10/C11 to confirm.
GATE_PTYPES = 0x67
CMDS = [0xC000C02,0xC000C03,0xC000C0B,0xC000C11,0xC000C20,0xC000C04,0xC000C05,0xC000C10]
SIZE_CHOICES = [4,16,64,0x100,0x400,0x40,0x80,0x1000]   # all NON-ZERO so param[1] rsp is never null
PUT_CMD_IN_BODY = False   # also write cmd as first u32 of params[0]
MAXBUF = 0x1800


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
