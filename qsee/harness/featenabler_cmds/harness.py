from .params import *
from qiling import Qiling
import struct, os

# === featenabler full-command sweep / bounds re-check =======================
# Target: Xiaomi/Qualcomm garnet featenabler.ta (DisplayCore feature-license TA).
#
# Staging (featenabler.json): GP lifecycle stubbed (returns TEE_SUCCESS);
# InvokeCommand points DIRECTLY at process_cmd@0x630.
#   ABI (verified): x0 = req ptr, w1 = req_len, x2 = rsp ptr, w3 = rsp_len.
#   cmd_id = *(u32*)req. Dispatch (jump table @0x8d78): cmd 0..4 + 0x64.
# Per-arm floors: every handler needs req_len>=0x44; cmd2(0x8d0)/cmd3(0x100c)
# additionally need rsp_len>=0xfbc. We always pass req_len=REQ_SIZE,
# rsp_len=RSP_SIZE (both >= the floors) so the fuzzer reaches the handler body.
#
# A prior STATIC pass called featenabler "clean" (req-controlled input limited
# to cmd_id + two boolean bytes req[4]/req[8]; feature payloads come from RPMB /
# qsee services, not the GP request). This harness RE-CHECKS that DYNAMICALLY:
# AFL drives cmd_id (-> {0,1,2,3,4,0x64}) and the full request body; the mink/
# qsee_stor/qsee_open service replies default to 0 (empty feature lists ->
# the bounded default branches). We watch for ANY heap-redzone OOB
# (PC=0xdeadbeef) or unmapped fault (the dispatcher / handlers mishandling a
# length). Benign return -> x30 = AFL_EXIT.
#
# The two boolean bytes (req[4], req[8]) and cmd_id are the real NW attack
# surface; the rest of req is mutated too in case the static "only 2 bytes
# matter" claim missed a field.

AFL_EXIT = 0x13370

REQ_BASE = 0x51000000
REQ_SIZE = 0x2000           # >= 0x44 floor, plenty of room for any req field
RSP_BASE = 0x52000000
RSP_SIZE = 0x2000           # >= 0xfbc floor for cmd2/cmd3

VALID_CMDS = [0, 1, 2, 3, 4, 0x64]

# fixed cmd override (single-seed repro); else cmd_id derived from input[0].
FORCE_CMD = os.environ.get("FT_CMD")


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, size, name in ((REQ_BASE, REQ_SIZE, "req"), (RSP_BASE, RSP_SIZE, "rsp")):
        try:
            ql.mem.map(base, size, info=f"[ft] {name}")
        except Exception as e:
            ql.log.warning(f"[ft] map {name}: {e}")
    print(f"[ft] init: req@{hex(REQ_BASE)} rsp@{hex(RSP_BASE)}")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # Layout of the AFL input:
    #   [0]      cmd selector (-> VALID_CMDS[sel % 6])
    #   [1..]    request body bytes (written verbatim from req[0]; we then
    #            stamp cmd_id over req[0..4] so the dispatch routes correctly).
    if FORCE_CMD is not None:
        cmd = int(FORCE_CMD, 0)
    else:
        sel = input[0] if len(input) >= 1 else 0
        cmd = VALID_CMDS[sel % len(VALID_CMDS)]

    req = bytearray(REQ_SIZE)
    # fill the request body with the fuzzer's remaining bytes (covers req[4]/req[8]
    # boolean bytes AND any other field, in case static missed one).
    body = input[1:] if len(input) > 1 else b""
    body = body[:REQ_SIZE - 4]
    req[4:4 + len(body)] = body
    # cmd_id at req[0]
    struct.pack_into("<I", req, 0, cmd & 0xFFFFFFFF)

    ql.mem.write(REQ_BASE, bytes(req))
    ql.mem.write(RSP_BASE, b"\x00" * RSP_SIZE)

    setup_params_fuzz(ql, cmd, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # process_cmd(x0=req, w1=req_len, x2=rsp, w3=rsp_len)
    ql.arch.regs.x0 = REQ_BASE
    ql.arch.regs.x1 = REQ_SIZE
    ql.arch.regs.x2 = RSP_BASE
    ql.arch.regs.x3 = RSP_SIZE
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[ft] cmd={cmd:#x} req_len={REQ_SIZE:#x} rsp_len={RSP_SIZE:#x} body={len(body)}B")
    return True
