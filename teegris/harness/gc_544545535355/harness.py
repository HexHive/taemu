# GlobalConfusion dynamic probe — TEESSU (544545535355), cmd 0x52.
# Static (globalconfusion_teegris.md): teessu_check_params@0x16b94 runs first,
# per-slot EXACT LUT pin loop @0x16ecc-0x16f9c ((paramTypes>>4i & 0xF)==expected[i]),
# then CheckMemoryAccessRights on slot0 IN @0x17140 / slot1 OUT @0x17188 / slot2 OUT @0x171d4.
# cmd 0x52 expects [slot0=MEMREF_IN(5), slot2=MEMREF_OUT(6)] (setup @0x16da8) -> base ptypes 0x605.
# PROBE: flip slot0 nibble 5->VALUE_IN(1) and pass ValueParam(POISON). If the TA pins,
# the nibble mismatch (1 != 5) rejects with -0xfffa BEFORE any deref => SAFE.
import os
from .params import *
from qiling import Qiling

CMD         = int(os.environ.get("GC_CMD", "0x52"), 0)
BASE_PTYPES = int(os.environ.get("GC_PTYPES", "0x605"), 0)  # cmd 0x52: [slot0=MEMREF_IN(5), slot2=MEMREF_OUT(6)]
FLIP_SLOTS  = [int(x, 0) for x in os.environ.get("GC_FLIP", "0").split(",")]
POISON      = 0x4142434445   # unmapped, SWd-looking
MEMREF_SIZE = 0x400


def _flip(base, slots):
    pt = base
    for i in slots:
        pt = (pt & ~(0xF << (4 * i))) | (0x1 << (4 * i))
    return pt


def place_input_callback(ql: Qiling, input: bytes, _: int):
    pt = _flip(BASE_PTYPES, FLIP_SLOTS)
    print(f"[GC-PROBE] TEESSU cmd={CMD:#x} base_ptypes={BASE_PTYPES:#x} -> flipped={pt:#x} "
          f"flip_slots={FLIP_SLOTS} POISON={POISON:#x}")
    params = [NoneParam(), NoneParam(), NoneParam(), NoneParam()]
    for i in range(4):
        nib = (BASE_PTYPES >> (4 * i)) & 0xF
        if i in FLIP_SLOTS:
            params[i] = ValueParam(POISON & 0xffffffff, (POISON >> 32) & 0xffffffff)
        elif nib in (5, 6, 7):
            params[i] = MemRefParam(bytes(MEMREF_SIZE), MEMREF_SIZE)
        elif nib in (1, 2, 3):
            params[i] = ValueParam(0, 0)
    setup_params_fuzz(ql, CMD, pt, params)
    return True
