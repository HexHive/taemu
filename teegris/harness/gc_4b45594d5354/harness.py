# GlobalConfusion NEGATIVE CONTROL — KEYMST (4b45594d5354).
# Static (globalconfusion_teegris.md): SINGLE COVERING ENTRY-PIN cmp w21,#0x65; b.ne reject
# @0x2c3fc (REE login==4 path) & @0x2c484 (TRUSTED_APP path), BEFORE any slot deref +
# IsREESharedMemory(1)@0x2c628,(2)@0x2c654. base ptypes 0x65 = [slot0=MEMREF_IN(5),
# slot1=MEMREF_OUT(6)]. EXPECTATION: any flip to VALUE breaks paramTypes==0x65 -> MUST be
# REJECTED (validates that the harness correctly detects the pin). NB: KEYMST ALSO has a
# login-method gate @0x2c344/@0x2c3f4 (REE login==4 / TRUSTED_APP) that runs before the pin;
# the emulator's TEE_GetPropertyAsIdentity returns TEE_LOGIN_PUBLIC(0), so the *login* gate
# may reject first (also a valid "rejected" outcome). Either way: NO poison deref.
import os
from .params import *
from qiling import Qiling

# To reach KEYMST's paramTypes==0x65 PIN (not its earlier login gate), run with
# TAEMU_FORCE_LOGIN=4 (the emulator's TEE_GetPropertyAsIdentity honours it; default
# TEE_LOGIN_PUBLIC(0) makes KEYMST reject at the login gate).

CMD         = int(os.environ.get("GC_CMD", "0x0"), 0)
BASE_PTYPES = int(os.environ.get("GC_PTYPES", "0x65"), 0)   # [slot0=MEMREF_IN(5), slot1=MEMREF_OUT(6)]
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
    print(f"[GC-PROBE] KEYMST(neg-ctl) cmd={CMD:#x} base_ptypes={BASE_PTYPES:#x} -> "
          f"flipped={pt:#x} flip_slots={FLIP_SLOTS} POISON={POISON:#x}")
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
