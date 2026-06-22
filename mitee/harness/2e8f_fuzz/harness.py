# === F7 / 2e8fade5 migpese eSE — GlobalConfusion probe + APDU structure drive ====
# Staged klee build (Invoke @0x22538). cmd dispatch (re-derived from the staged .ta):
#   group 0x1000000x (jump table @0x8b77, base 0x22678):
#     0x10000000 -> 0x22678 -> bl 0x1ffd8  GPMESE_Transceive (APDU header routing)
#     0x10000001 -> 0x226cc -> bl 0x1fb68  GPMESE_Open
#     0x10000002 -> 0x226dc -> bl 0x1fe20  GPMESE_Close
#     0x10000003 -> 0x226ec -> bl 0x21120  GPMESE_Transceive_Raw
#   group 0x2000000x:
#     0x20000000 -> bl 0x21250  GPMESE_Generic (subcmd in params[0] VALUE)
#     0x20000001 -> bl 0x21368  GPMESE_Preshared_Secret
#     0x20000002 -> bl 0x219f0  GPMESE_Get_EncRot_NXP
#     0x20000003 -> bl 0x21250? (Check_BaseKey path)
#
# GATE for Transceive (0x1ffd8): paramTypes==0x65, params[0].size>=4, params[1].size!=0.
#   Reads APDU header apdu[0..4] from params[0].buffer (size only >=4 -> apdu[4] is a
#   1-byte over-read when size==4). Magic FFFFABCD -> sub_20278. apdu[1]==0x70 ->
#   MANAGE CHANNEL. apdu[2]==0,apdu[0]>=4,apdu[0]&0xf0==0x40,apdu[4]==1 -> channel-open.
#
# The entry @0x22538 does NOT validate paramTypes before dispatch; each handler does.
# MODE is selected by env TAEMU_F7_MODE:
#   gc        : GlobalConfusion probe — flip param slots to VALUE(poison), see if a
#               handler derefs the poison as a buffer pointer (misa/S19-style).
#   apdu_short: Transceive with params[0].size==4 exactly -> apdu[4] over-read probe.
#   apdu_mc   : Transceive MANAGE-CHANNEL-open frame, vary Lc/body lengths.
#   apdu_magic: Transceive FF FF AB CD magic header -> sub_20278 parser, vary body.
#   raw       : Transceive_Raw (0x10000003) with attacker APDU + tiny output buffer.
from .params import *
from qiling import Qiling
import struct, os

MODE   = os.environ.get("TAEMU_F7_MODE", "gc")
CMD    = int(os.environ.get("F7_CMD", "0x10000000"), 0)
POISON = int(os.environ.get("F7_POISON", "0x4142434445"), 0)
FLIP   = os.environ.get("F7_FLIP", "0,1")
FLIP_SLOTS = [int(x) for x in FLIP.split(",") if x != ""]
LC     = int(os.environ.get("F7_LC", "0"), 0)          # APDU Lc field (length of body)
P0SZ   = int(os.environ.get("F7_P0SZ", "0"), 0)        # 0 = auto
P1SZ   = int(os.environ.get("F7_P1SZ", "0x100"), 0)


def _emit(ql, cmd, pt, params):
    setup_params_fuzz(ql, cmd, pt, params)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    if MODE == "gc":
        # poison the flipped slots as VALUE; honest paramTypes = VALUE_INPUT nibbles.
        pt = 0
        for i in FLIP_SLOTS:
            pt |= (0x1 << (4 * i))
        params = [NoneParam(), NoneParam(), NoneParam(), NoneParam()]
        lo = POISON & 0xffffffff
        hi = (POISON >> 32) & 0xffffffff
        for i in FLIP_SLOTS:
            params[i] = ValueParam(lo, hi)
        print(f"[F7 GC] cmd={CMD:#x} pt={pt:#06x} POISON={POISON:#x} FLIP={FLIP_SLOTS}")
        _emit(ql, CMD, pt, params)
        return True

    # ---- structure-aware APDU drives (cmd 0x10000000 Transceive / 0x10000003 Raw) ----
    if MODE == "apdu_short":
        # params[0].size == 4 exactly: apdu[0..3] in-bounds, apdu[4] over-read.
        apdu = bytes([0x00, 0x00, 0x00, 0x00])   # CLA INS P1 P2 ; no Lc byte present
        p0 = apdu
        sz = 4
        print(f"[F7 apdu_short] Transceive params[0].size=4 -> apdu[4] over-read probe")
        params = [MemRefParam(p0, sz), MemRefParam(bytes(P1SZ), P1SZ), NoneParam(), NoneParam()]
        _emit(ql, 0x10000000, 0x65, params)
        return True

    if MODE == "apdu_mc":
        # MANAGE CHANNEL OPEN-shaped header: apdu[1]==0x70, apdu[2]==0, apdu[0]>=4 &
        # (apdu[0]&0xf0)==0x40, apdu[4]==1. Then body length = Lc drives sub-parse.
        lc = LC if LC else (input[0] if input else 0)
        header = bytes([0x40, 0x70, 0x00, 0x00, 0x01]) + bytes([lc & 0xff])
        body = bytes((input[1:1 + (lc & 0xff)] if input else b"") )
        body = body.ljust(lc & 0xff, b"\x41")
        p0 = header + body
        sz = P0SZ if P0SZ else len(p0)
        print(f"[F7 apdu_mc] Transceive MANAGE-CHANNEL Lc={lc & 0xff:#x} p0sz={sz:#x}")
        params = [MemRefParam(p0, sz), MemRefParam(bytes(P1SZ), P1SZ), NoneParam(), NoneParam()]
        _emit(ql, 0x10000000, 0x65, params)
        return True

    if MODE == "apdu_magic":
        # FF FF AB CD magic at apdu[0..3] ((apdu[0]&apdu[1])==0xff, apdu[2]==0xab,
        # apdu[3]==0xcd) -> sub_20278(out=params[1].buf, &state). vary trailing body.
        body = (input if input else b"")
        p0 = bytes([0xFF, 0xFF, 0xAB, 0xCD]) + body
        sz = P0SZ if P0SZ else len(p0)
        print(f"[F7 apdu_magic] Transceive magic FFFFABCD bodysz={len(body):#x} p0sz={sz:#x}")
        params = [MemRefParam(p0, sz), MemRefParam(bytes(P1SZ), P1SZ), NoneParam(), NoneParam()]
        _emit(ql, 0x10000000, 0x65, params)
        return True

    if MODE == "raw":
        # Transceive_Raw 0x10000003: send the C-APDU straight to FP-gate. tiny out buf.
        apdu = (input if input else bytes([0x80, 0xF0, 0x01, 0x01, 0x00]))
        sz = P0SZ if P0SZ else len(apdu)
        outsz = P1SZ if P1SZ else 1
        print(f"[F7 raw] Transceive_Raw apdusz={sz:#x} outsz={outsz:#x}")
        params = [MemRefParam(apdu, sz), MemRefParam(bytes(outsz), outsz), NoneParam(), NoneParam()]
        _emit(ql, 0x10000003, 0x65, params)
        return True

    # default: gc
    print("[F7] unknown MODE, defaulting to noop NONE params")
    _emit(ql, CMD, 0, [NoneParam()] * 4)
    return True
