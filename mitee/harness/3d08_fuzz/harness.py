# from params import *
from .params import * 
from pwn import *
from qiling import Qiling
import struct, os

# === vsimapp (3d08821c) — Xiaomi Virtual SIM =================================
# Staged build sha 737e2823… (klee). Dispatch RE'd from the staged .ta:
#   TA_InvokeCommandEntryPoint @0x26190:
#     a1=w21=cmd_id, a2=w19=paramTypes, a3=x20=&params.
#     GATE: paramTypes==0x65 ; params[0].size==0x608(1544) ; params[1].size==0x608 ;
#           *(u32*)param0.buf == 1 (version) ; in_bodylen=[buf+4]<=0x600 ;
#           out_bodylen=[param1.buf+4]<0x601.
#   handler(in=param0.buf, out=param1.buf [, mode]):
#     cmd 0x1000 sim_add@0x226d0 ; 0x1001 sim_del@0x22888 ; 0x1002 sim_get@0x22a18 ;
#     0x1003 sim_list@0x22e70 ; cmd1/2 sim_auth@0x230e0 ; 0x2000 query@0x20cf0 ;
#     0x2001 enroll@0x20550 ; 0x2002 enroll_export@0x20d98.
#   GlobalConfusion: NOT applicable (paramTypes==0x65 + both sizes pinned before deref).
#
# Reachable WITHOUT enroll/storage state (no enroll_key / /sim file present):
#   - request-header parse for every cmd (version==1, bodylen bound) -- BOUNDED.
#   - sim_del/get/list IMSI parse (18-byte ASCII-hex -> 9-byte) + dir enum.
#   - sim_auth request parse up to the /sim/<imsi> lookup (then sim-not-found).
# Crypto-gated (need enroll_key): sim_add v1/v2/v3 RSA-decrypt; sim_auth deep v1/v2/v3.
#
# Modes: CMD3D=<cmd_id> pins one cmd; else AFL byte0 picks from the cmd list.
#   The harness always sets version=1 and a valid bodylen so AFL reaches the parser.

CMD_ENV = os.environ.get("CMD3D")
PTYPES = 0x65
SZ = 0x608
CMDS = [0x1000, 0x1001, 0x1002, 0x1003, 1, 2, 0x2000, 0x2001, 0x2002]


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 1:
        return False
    if CMD_ENV is not None:
        cmd = int(CMD_ENV, 0)
        body = input
    else:
        cmd = CMDS[input[0] % len(CMDS)]
        body = input[1:]
    # build a well-formed input frame: [u32 version=1][u32 bodylen][body...]
    blen = min(len(body), SZ - 8)
    frame = struct.pack("<II", 1, blen) + body
    frame = frame[:SZ].ljust(SZ, b"\x00")
    print(f"[3d08] cmd={cmd:#x} ptypes=0x65 version=1 bodylen={blen:#x}")
    command_params = [
        MemRefParam(frame, SZ),                                  # param0 INPUT
        MemRefParam(struct.pack("<II", 0, 0) + bytes(SZ - 8), SZ),  # param1 OUTPUT (hdr ver/len=0)
        NoneParam(),
        NoneParam(),
    ]
    setup_fuzz(ql, cmd, PTYPES, command_params, input)
    return True
