# GlobalConfusion dynamic probe — generic (driver/stub TAs). Declares slot0 VALUE with a
# POISON pointer. For TAs whose InvokeCommand never touches x3/params (socket/ioctl-only),
# the poison is structurally unreachable -> clean return, confirming NO GP params channel.
import os
from .params import *
from qiling import Qiling

CMD         = int(os.environ.get("GC_CMD", "0x0"), 0)
BASE_PTYPES = int(os.environ.get("GC_PTYPES", "0x1"), 0)   # slot0=VALUE_IN by default
FLIP_SLOTS  = [int(x, 0) for x in os.environ.get("GC_FLIP", "0").split(",")]
POISON      = 0x4142434445
MEMREF_SIZE = 0x400


def _flip(base, slots):
    pt = base
    for i in slots:
        pt = (pt & ~(0xF << (4 * i))) | (0x1 << (4 * i))
    return pt


def place_input_callback(ql: Qiling, input: bytes, _: int):
    pt = _flip(BASE_PTYPES, FLIP_SLOTS)
    print(f"[GC-PROBE] driver/stub cmd={CMD:#x} base_ptypes={BASE_PTYPES:#x} -> flipped={pt:#x} "
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
