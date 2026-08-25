#!/usr/bin/env python3
"""Generate a self-contained structure-aware TLV fuzz harness.py for a TEEGRIS
TA whose InvokeCommand input MEMREF is a `[u32 cmd_id][u32 payload_len][TLV..]`
envelope (FbCkmR, HvAUtW: tz_process_command reads cmd_id from the first u32 of
params[0] then runs a TLV deserialiser).

Why a generator: each harness.py is loaded by ta_mgr via spec_from_file_location
with __package__ = "emulate", so `from .params import *` resolves to
emulate.params -- but a harness CANNOT import a sibling helper module the same
way. So every harness must be self-contained; we stamp the per-TA constants in.
"""
import sys

TEMPLATE = r'''# AUTO-GENERATED structure-aware TLV fuzz harness for {NAME} ({TAIL}).
# Drives TA_InvokeCommandEntryPoint with a MUTATED [cmd_id][payload_len][TLV..]
# envelope in params[0] (the MEMREF input). The three task knobs:
#   - command id  : the first u32 of the body (what tz_process_command reads),
#                   biased to the documented handler cmd ids.
#   - param-type  : usually the gate value {PTYPES_HEX} (so we get PAST the
#                   param-types check and into tz_process_command), but a slice
#                   of inputs fuzz it raw to probe the gate itself.
#   - memref sizes+contents : the TLV item tags/lengths/payloads are fuzzed, and
#                   each item's declared `len` is drawn from the input (so a
#                   declared length can EXCEED the bytes actually present -> the
#                   deserialiser's bounds handling is exercised); the param
#                   buffers are redzoned (params.py) so an OOB read past the
#                   granted request size or OOB write past the response trips
#                   CRASH_PC.
from .params import *
from qiling import Qiling
import struct

GATE_PTYPES = {PTYPES_HEX}
CMDS = {CMDS}
# documented bytes/scalar TLV tags for this TA (used as a tag palette so a
# meaningful fraction of fuzzed items carry a tag the handler actually fetches);
# the high byte (0x01 scalar / 0x02 bytes) is respected.
TAGS = {TAGS}
REQ_BUF = {REQ_BUF}     # granted size of the input MEMREF (params[0])
RSP_BUF = {RSP_BUF}     # granted size of the output MEMREF (params[1])


def _u32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    # input[0]      : cmd selector
    # input[1]      : control byte (ptypes-raw flag, item count, length-skew)
    # input[2:]     : a byte pool consumed to synthesise TLV items
    cmd = CMDS[input[0] % len(CMDS)]
    ctrl = input[1]
    pool = input[2:]
    pp = 0

    def take(n):
        nonlocal pp
        b = pool[pp:pp + n]
        pp += n
        return b

    # ptypes: 7/8 of the time the gate value (reach the handler), 1/8 raw fuzz.
    if (ctrl & 0xE0) == 0xE0:
        ptypes = struct.unpack_from('<H', input, 4)[0] if len(input) >= 6 else GATE_PTYPES
    else:
        ptypes = GATE_PTYPES

    nitems = (ctrl & 0x7) + 1            # 1..8 TLV items
    body = bytearray()
    body += _u32(cmd)                    # [0] cmd_id
    body += _u32(0)                      # [4] payload_len placeholder
    for _i in range(nitems):
        sel = take(1)
        if not sel:
            break
        s = sel[0]
        # pick a tag: mostly from the documented palette, sometimes fully fuzzed
        if (s & 0x80) and len(TAGS):
            tag = TAGS[s % len(TAGS)]
        else:
            tag = int.from_bytes(take(4).ljust(4, b'\x00'), 'little')
        hi = (tag >> 24) & 0xFF
        if hi == 0x01:                   # scalar item: [tag][value]
            val = int.from_bytes(take(4).ljust(4, b'\x00'), 'little')
            body += _u32(tag) + _u32(val)
        else:                            # bytes item: [tag][len][len bytes]
            # declared length: from the input, sometimes deliberately LARGER
            # than the data we actually append (exercise bounds handling).
            dlen_sel = take(2)
            dlen = int.from_bytes(dlen_sel.ljust(2, b'\x00'), 'little')
            dlen %= (REQ_BUF + 0x40)     # may exceed buffer -> OOB read probe
            ndata = min(dlen, max(0, len(pool) - pp))
            data = take(ndata)
            if (s & 0x40):               # skew: declare more than provided
                pass                     # leave dlen as-is (> ndata)
            else:
                dlen = ndata             # honest length
            body += _u32(tag) + _u32(dlen) + bytes(data)

    # payload_len invariant: L == total - 8 (the deserialiser checks this); but
    # 1/8 of the time corrupt it to probe the length check.
    L = len(body) - 8
    if (ctrl & 0x18) == 0x18:
        L = struct.unpack_from('<H', input, 6)[0] if len(input) >= 8 else L
    body[4:8] = _u32(L)

    in_size = REQ_BUF
    in_buf = bytes(body[:in_size]).ljust(in_size, b'\x00')

    # ptypes nibble1 decides whether params[1] is present; for the gate value
    # ({PTYPES_HEX}) it is a memref, so always supply the response buffer.
    command_params = [
        MemRefParam(in_buf, in_size),
        MemRefParam(b'\x00' * RSP_BUF, RSP_BUF),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
'''


def main():
    name = sys.argv[1]
    tail = sys.argv[2]
    ptypes = sys.argv[3]
    cmds = sys.argv[4]
    tags = sys.argv[5]
    req = sys.argv[6]
    rsp = sys.argv[7]
    out = sys.argv[8]
    txt = TEMPLATE.format(NAME=name, TAIL=tail, PTYPES_HEX=ptypes, CMDS=cmds,
                          TAGS=tags, REQ_BUF=req, RSP_BUF=rsp)
    with open(out, 'w') as f:
        f.write(txt)
    print(f'wrote {out}')


if __name__ == '__main__':
    main()
