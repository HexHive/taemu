# Generic mutational fuzz harness for sbxpxy (534258505859), shipping SFDZE1.
# sbxpxy = CryptoManager Strongbox/Sandbox PROXY (SSP_PX). (The campaign-4 prompt
# called this uuid "smcdrv" — that was wrong: real smcdrv is 000000020081, a
# display driver with an EMPTY InvokeCommand stub. This 534258505859 binary is
# sbxpxy, which DOES have a REE-direct command surface.) Mid-tier hunt marked
# sbxpxy CLEAN-confirmed (IPC marshal/unmarshal lengths clamped; ungated
# 0xF001/0xF003 bounded) — this is a dynamic re-check of that REE surface.
#
# Dispatcher RE (objdump): TA_InvokeCommandEntryPoint @0x547c -> inner @0x5880, a
# jump-table over cmd ids 0x1000..0x1015 (sub w8,w19,#1; cmp w8,#0x15; ldrh
# [tbl+w8*2]; br) PLUS discrete 0x1001/0x1002/0x1004/0xf001/0xf003. Each handler
# (e.g. cmd 0x1001 @0x60f0) checks param_type low nibble == 7, TEES_IsREESharedMemory,
# runs nwd_param_validate_ssp_msg, then memcpy's a REE memref (size capped 0x8000).
# param[0]/[1] redzoned (params.py) so OOB trips CRASH_PC.
from .params import *
from qiling import Qiling
import struct

# cmd ids: the jump-table range 0x1000..0x1015 + the discrete ones.
CMDS = [0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1008,
        0x1009, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0x1010, 0x1011,
        0x1012, 0x1013, 0x1014, 0x1015, 0xf001, 0xf003]
PTYPES_CHOICES = [0x7, 0x77, 0x17, 0x57, 0x75, 0x67, 0x577, 0x77]
REQ_SIZES = [0x8, 0x10, 0x20, 0x40, 0x80, 0xb1, 0x100, 0x200, 0x400, 0x1, 0x4,
             0x800, 0x1000]
RSP_SIZES = [0x8, 0x10, 0x20, 0x2c, 0xb0, 0xb1, 0x40, 0x100, 0x200, 0x4, 0x400]
MAXBUF = 0x1100


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    ptypes = PTYPES_CHOICES[input[1] % len(PTYPES_CHOICES)]
    req_size = min(REQ_SIZES[input[2] % len(REQ_SIZES)], MAXBUF)
    rsp_size = min(RSP_SIZES[input[3] % len(RSP_SIZES)], MAXBUF)
    body = input[8:]

    command_params = []
    off = 0
    for i in range(4):
        pt = (ptypes >> (4 * i)) & 0xF
        if pt in (1, 2, 3):
            a = int.from_bytes(body[off:off + 4].ljust(4, b'\x00'), 'little'); off += 4
            b = int.from_bytes(body[off:off + 4].ljust(4, b'\x00'), 'little'); off += 4
            command_params.append(ValueParam(a, b))
        elif pt in (4, 5, 6, 7):
            size = req_size if i == 0 else rsp_size
            if pt == 5:  # output only
                command_params.append(MemRefParam(b'\x00' * size, size))
            else:
                chunk = body[off:off + size]; off += len(chunk)
                command_params.append(MemRefParam(bytes(chunk).ljust(size, b'\x00'), size))
        else:
            command_params.append(NoneParam())
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
