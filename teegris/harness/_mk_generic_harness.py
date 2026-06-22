#!/usr/bin/env python3
"""Generate a self-contained generic mutational fuzz harness.py for a TEEGRIS
TA whose InvokeCommand dispatcher enforces an exact param-types value and
(often) exact memref sizes, and reads its sub-command + payload from the
request MEMREF body.

The three task knobs:
  - command id  : the GP InvokeCommand cmd id (CMDS palette) AND, since several
                  TEEGRIS TAs read a sub-cmd from the first u32 of params[0],
                  the body's first u32 is also set from the same selector.
  - param-type  : fixed to the gate value so we reach the handler (a slice fuzz
                  it raw).
  - memref sizes+contents : sizes drawn from SIZE_CHOICES (which INCLUDES the
                  TA's documented exact sizes so we pass the size gate), bodies
                  fuzzed from the input. Param buffers redzoned (params.py).
"""
import sys

TEMPLATE = r'''# AUTO-GENERATED generic mutational fuzz harness for {NAME} ({TAIL}).
from .params import *
from qiling import Qiling
import struct

GATE_PTYPES = {PTYPES_HEX}
CMDS = {CMDS}
SIZE_CHOICES = {SIZES}        # includes the TA's documented exact memref sizes
PUT_CMD_IN_BODY = {PUT_CMD_IN_BODY}   # also write cmd as first u32 of params[0]
MAXBUF = {MAXBUF}


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
'''


def main():
    name, tail, ptypes, cmds, sizes, putcmd, maxbuf, out = sys.argv[1:9]
    txt = TEMPLATE.format(NAME=name, TAIL=tail, PTYPES_HEX=ptypes, CMDS=cmds,
                          SIZES=sizes, PUT_CMD_IN_BODY=putcmd, MAXBUF=maxbuf)
    with open(out, 'w') as f:
        f.write(txt)
    print(f'wrote {out}')


if __name__ == '__main__':
    main()
