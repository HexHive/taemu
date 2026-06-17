# GlobalConfusion dynamic probe — esecom (657365636f6d).
# Static (globalconfusion_teegris.md): exact covering pin paramTypes==0x67 @0x85c4
# (after NULL+size gates @0x84ec..0x8580) + esecom_check_ree_mem@0x8724 =
# IsREESharedMemory(3)@0x8748 & (2)@0x8770. base ptypes 0x67 = [slot0=MEMREF_INOUT(7),
# slot1=MEMREF_OUT(6)]; both slots' buffers (+0/+0x10) and sizes (+8/+0x18) read at entry,
# size gated to [0x1018, 0x2030]. PROBE: flip a memref slot to VALUE(1) with ValueParam(POISON).
# A VALUE slot writes [a:4][b:4][pad:8] -> buffer overlap = POISON, size overlap = 0; so the
# size gate (size<0x1018) rejects, AND the pin (paramTypes!=0x67) rejects -> SAFE either way.
import os
from .params import *
from qiling import Qiling

CMD         = int(os.environ.get("GC_CMD", "0x0"), 0)     # any cmd; gates run before dispatch
BASE_PTYPES = int(os.environ.get("GC_PTYPES", "0x67"), 0)  # [slot0=MEMREF_INOUT(7), slot1=MEMREF_OUT(6)]
FLIP_SLOTS  = [int(x, 0) for x in os.environ.get("GC_FLIP", "0").split(",")]
POISON      = 0x4142434445
GOOD_SIZE   = 0x1018         # in the gated [0x1018, 0x2030] range so the unflipped slot passes


def _flip(base, slots):
    pt = base
    for i in slots:
        pt = (pt & ~(0xF << (4 * i))) | (0x1 << (4 * i))
    return pt


def place_input_callback(ql: Qiling, input: bytes, _: int):
    pt = _flip(BASE_PTYPES, FLIP_SLOTS)
    print(f"[GC-PROBE] esecom cmd={CMD:#x} base_ptypes={BASE_PTYPES:#x} -> flipped={pt:#x} "
          f"flip_slots={FLIP_SLOTS} POISON={POISON:#x}")
    params = [NoneParam(), NoneParam(), NoneParam(), NoneParam()]
    for i in range(4):
        nib = (BASE_PTYPES >> (4 * i)) & 0xF
        if i in FLIP_SLOTS:
            params[i] = ValueParam(POISON & 0xffffffff, (POISON >> 32) & 0xffffffff)
        elif nib in (5, 6, 7):
            params[i] = MemRefParam(bytes(GOOD_SIZE), GOOD_SIZE)
        elif nib in (1, 2, 3):
            params[i] = ValueParam(0, 0)
    setup_params_fuzz(ql, CMD, pt, params)
    return True
