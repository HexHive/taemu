#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === hw_proxy (9811c1f6) — Xiaomi MiTEE Identity Credential HAL ============
# Staged build sha e1ebabfc… (klee). Dispatch RE'd from the staged .ta:
#   TA_InvokeCommandEntryPoint @0x45ba0:
#     a1=w23=cmd_id, a2=w20=paramTypes, a3=x19=&params.
#     gate: cmp w20,#0x65 ; b.ne default  -> paramTypes MUST == 0x65
#       (0x65 = param0=MEMREF_INPUT(5), param1=MEMREF_OUTPUT(6), p2=p3=NONE).
#     x21 = params[0].buffer ([x19]) ; w20 = params[0].size ([x19+8]).
#     jump table @0x113e8 indexed by cmd_id (even 0..0x48 -> handler stub;
#       odd -> default error @0x4676c).
#   Each handler stub: op(EicObj* obj, in_buf=x21, in_len=w20=param0.size,
#                          out_buf=&slot, out_len=&slot).
#   So in_len is the GP param0 memref SIZE (attacker-controlled), and the op
#   parses in_buf[0..in_len]. The bugs are length/offset confusions INSIDE
#   the op parsers (param0.buffer is gated to be a real memref -> classic
#   GlobalConfusion memref->VALUE poison is REJECTED by the ==0x65 gate).
#
# Harness modes (env CMD pins a cmd; else AFL byte0 picks an even cmd):
#   - CMD: exact cmd_id (decimal/hex). default 0x14 (PresentInitialize).
#   - P0SIZE: override the GP param0 memref size handed to the op as in_len.
#       If unset, in_len == len(body) (the natural size).
#   The attacker body is input[1:] (or env SEED file content), placed in a
#   redzoned param0; param1 is a redzoned 0x1000 OUTPUT.

CMD_ENV = os.environ.get("CMD")
P0SIZE_ENV = os.environ.get("P0SIZE")
PTYPES = 0x65
OUTSZ = int(os.environ.get("OUTSZ", str(0x1000)), 0)

EVEN_CMDS = list(range(0, 0x49, 2))  # 0,2,...,0x48 — every real op

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 1:
        return False
    if CMD_ENV is not None:
        cmd = int(CMD_ENV, 0)
        body = input  # whole input is the op body when cmd is pinned
    else:
        cmd = EVEN_CMDS[input[0] % len(EVEN_CMDS)]
        body = input[1:]
    p0size = int(P0SIZE_ENV, 0) if P0SIZE_ENV is not None else len(body)
    # If the declared size exceeds the real body, pad so the redzone sits at
    # exactly p0size (the op will read up to in_len=p0size).
    if p0size > len(body):
        body = body + b"\x00" * (p0size - len(body))
    print(f"[9811] cmd={cmd:#x} paramTypes=0x65 in_len(param0.size)={p0size:#x} bodylen={len(body):#x}")
    command_params = [
        MemRefParam(body, p0size),            # param0 MEMREF_INPUT (redzoned)
        MemRefParam(bytes(OUTSZ), OUTSZ),     # param1 MEMREF_OUTPUT (redzoned)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)
    return True
