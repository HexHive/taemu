# Generic mutational fuzz harness for prvtee (505256544545), shipping SFDZE1.
# Dispatcher RE: TA_InvokeCommandEntryPoint @0x1a614 requires param[0] ptype==7
# (MEMREF_INOUT) at 0x1a694 (`and w8,w24,#0xf; cmp w8,#7; b.ne reject`); the
# pre-"gate" call 0x1c2b8 is only a stack-canary check (returns 0), NOT a login
# gate, so dispatch is reached. prvtee surface (strings): teeCmdExecuter.c, GAK
# secure-object wrap/unwrap (TEES_WrapSecureObject/UnwrapSecureObject),
# unwrapGakBlob ("Invalid GAK Blob length"), an ASN.1 generator (asn1_gen_field/
# asn1_gen_sequence), CSR unwrap. Findings on record (prvtee.md): GAK-SO forge
# (blocked at un-modeled TEES_WrapSecureObject) + unwrapGakBlob 4-B stack write
# (into dead padding, asan-unflaggable). This drive hunts for OTHER cmd OOB.
# param[0] (and optionally param[1]) are redzoned (params.py) so an OOB read past
# the request size or OOB write past the response trips CRASH_PC.
from .params import *
from qiling import Qiling
import struct

# low nibble 7 = param[0] MEMREF_INOUT (the gate). vary the other nibbles so
# handlers that want a 2nd memref/value param can also run.
PTYPES_CHOICES = [0x7, 0x77, 0x17, 0x67, 0x27, 0x777, 0x0067]
# GP-level cmd id (selects the framed-request path; the entry accepts a range —
# any value works as long as the framing+inner cmd are valid). Keep a couple.
GP_CMDS = [0x0, 0x1, 0x6]
# INNER command ids (req[0:4]) — the teeCmdExecuter @0x1a2d0 supports EXACTLY
# these 4 (else "Not supported command : 0x%X"): 0xa702 (idx15 handler), 0xa803
# (idx21), 0xa804 (idx15), 0xab07 (no-op-ish path). These reach the GAK/unwrap/
# ASN.1 handlers via bl 0x23f40. Bias all 4 equally; rare raw-fuzz to probe.
INNER_CMDS = [0xa702, 0xa803, 0xa804, 0xab07, 0xa702, 0xa803, 0xa804, 0xab07]
CMDS = GP_CMDS  # back-compat name used below for the GP cmd
REQ_SIZES = [0x4, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x1, 0x8, 0x800]
RSP_SIZES = [0x100, 0x100, 0x40, 0x20, 0x10, 0x400, 0x8, 0x80]


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    inner_cmd = INNER_CMDS[(input[0] >> 2) % len(INNER_CMDS)]
    ptypes = PTYPES_CHOICES[input[1] % len(PTYPES_CHOICES)]
    req_size = REQ_SIZES[input[2] % len(REQ_SIZES)]
    rsp_size = RSP_SIZES[input[3] % len(RSP_SIZES)]
    body = input[8:]
    req = bytearray(bytes(body[:req_size]).ljust(req_size, b'\x00'))
    # prvtee request framing (TA_InvokeCommandEntryPoint @0x1a820): the request
    # buffer carries a length field at req[4:8]; the entry checks
    # `req_len + 8 <= param[0].size` (0x1a824 add x8,x25,#8; cmp x8,x4; b.hi
    # reject "Request data length too big") then memcpy(req_len) into a heap copy
    # (0x1a84c) and dispatches the inner cmd from req[0:4] (w26 = ldr [x24],#8).
    # So put a VALID length in req[4:8] (else every input bounces) and an inner
    # cmd selector in req[0:4]. 6/8 honest length; 2/8 raw-fuzz it to probe gate.
    if req_size >= 8:
        if (input[1] & 0xC0) == 0xC0:
            pass  # leave req[4:8] raw-fuzzed (probe the length gate itself)
        else:
            inner_len = max(0, req_size - 8)
            req[4:8] = struct.pack('<I', inner_len)
        # inner cmd selector in req[0:4] (the actual prvtee command executed)
        req[0:4] = struct.pack('<I', inner_cmd & 0xFFFFFFFF)
    req = bytes(req)

    command_params = []
    for i in range(4):
        pt = (ptypes >> (4 * i)) & 0xF
        if pt in (1, 2, 3):
            a = struct.unpack_from('<H', input, 4)[0] if len(input) >= 6 else 0
            command_params.append(ValueParam(a, 0))
        elif pt in (5, 6, 7):
            if i == 0:
                command_params.append(MemRefParam(req, req_size))
            else:
                command_params.append(MemRefParam(b'\x00' * rsp_size, rsp_size))
        else:
            command_params.append(NoneParam())
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
