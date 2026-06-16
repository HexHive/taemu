# Mutational fuzz harness for HDCP (00000048444350), shipping SFDZE1 build.
# Dispatcher RE (TA_InvokeCommandEntryPoint @0xa99c):
#   - param[0] ptype must be 7 (MEMREF_INOUT), param[0].size <= 0x10017.
#   - param[1] ptype must be 7 (MEMREF_INOUT), both REE-shmem.
#   - req is TEE_Malloc'd + TEE_MemMove'd from param[0] (size=param[0].size).
#   - init gate hdcp_isInitialized @0xac5c THEN dispatcher hdcp_process_command
#     @0xa03c(cmd, req_copy, req_size, resp_buf, &resp_size).
# CRITICAL — the init gate (0xac5c) is per-cmd:
#   * cmds 0x82, 0x94, 0x95, 0x97, 0x98  -> RETURN 1 UNCONDITIONALLY (no bootstrap!)
#   * cmds 0x7a, 0x7e, 0xdd, 0xe6        -> gate on byte_23400
#   * everything else                    -> gate on byte_23401
# So we bias the COLD-REACHABLE cmds (0x82/0x94/0x95/0x97/0x98) heavily — they
# reach their handler with no bootstrap. The response buffer is kept SMALL so an
# unchecked handler write (cmd 0x94 hardcodes 880 B) overflows it -> redzone
# CRASH_PC. Request size is fuzzed (some handlers fast-path on small sizes, e.g.
# the cmd-0xD2 16-B over-read needs req_size small).
from .params import *
from qiling import Qiling
import struct

GATE_PTYPES = 0x77   # param[0]=MEMREF_INOUT, param[1]=MEMREF_INOUT
# cold-reachable cmds first (bypass init gate), then the byte_23400/23401 set
# (harmless to try; they bounce at the gate, cheap). Weighted to the cold ones.
CMDS = [0x94, 0x95, 0x97, 0x98, 0x82, 0x94, 0x95, 0x97, 0x98, 0x82,
        0x70, 0x72, 0x77, 0x78, 0x7a, 0x7e, 0xd2, 0xdb, 0xdd, 0xe6]
# request sizes: small (fast-paths / 1-byte over-reads), mid, and near the
# 0x10017 cap. Bias small + 0x384 (the cmd-0x94 minimum) regions.
REQ_SIZES = [0x1, 0x4, 0x10, 0x40, 0x100, 0x384, 0x385, 0x400, 0x800, 0x2, 0x8, 0x20]
# response buffer sizes: keep SMALL so unchecked writes overflow -> redzone.
RSP_SIZES = [0x10, 0x10, 0x8, 0x20, 0x40, 0x4, 0x80, 0x100]


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 8:
        return False
    cmd = CMDS[input[0] % len(CMDS)]
    sel = input[1]
    if (sel & 0xE0) == 0xE0:
        ptypes = struct.unpack_from('<H', input, 4)[0]
    else:
        ptypes = GATE_PTYPES
    req_size = REQ_SIZES[input[2] % len(REQ_SIZES)]
    rsp_size = RSP_SIZES[input[3] % len(RSP_SIZES)]
    body = input[8:]
    req = bytes(body[:req_size]).ljust(req_size, b'\x00')

    command_params = [
        MemRefParam(req, req_size),                 # params[0] = req (INOUT)
        MemRefParam(b'\x00' * rsp_size, rsp_size),  # params[1] = resp (small)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, ptypes, command_params)
    return True
