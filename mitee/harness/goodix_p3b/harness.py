from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === goodix_fp (a734eed9) STATEFUL parser harness — Phase-3 P3b ==============
#
# GOAL: reach the REAL calibration/matcher/template parsers that Wave-2 could
# not, because they deref three GLOBAL session-pointer slots that are ZERO at
# load (BSS) until gf_sensor_init builds them:
#   slotB = 0xC0C308  ( *(0xC006F0) ) -> sess_B  fpcore/finger-list mgr; [+0x18]=tmpl list
#   slotA = 0xC0C338  ( *(0xC006F8) ) -> sess_A  sensor/chip session (dims/id at +8..+0x24)
#   slotC = 0xC0C328  ( *(0xC00700) ) -> sess_C  algo/matcher session; vtable @ +0x8/+0x60/+0xc0
# Handlers do `sess = *(slot)` then deref sess -> NULL deref when unprimed
# (= Wave-2's 7 false-positive crashes, goodix_fp_state_fps/TRIAGE.md).
#
# WHY init_fuzz STUB (not the real prime command):
#   The real installer is module 0x3EA (sensor) sub 2 = gf_sensor_init @0xDF728.
#   Running it in-emulator FAULTS at 0xdff44 (strlen on an unmapped gf_config.c
#   "screen_refresh_rate" string ptr) because it probes the unmodeled Goodix G3T
#   SPI sensor + reads board config the emulator has no backing for. (Verified:
#   `check_config exit. err=GF_ERROR_BAD_PARAMS errno=1004` -> READ_UNMAPPED.)
#   Per the campaign rule "model documented peer gates, never invent hardware",
#   we STUB the install: allocate zeroed session objects and write their pointers
#   into the 3 BSS slots so `sess = *(slot)` is NON-NULL and the handler proceeds
#   into its REE-input length parsing instead of NULL-deref'ing.
#
#   *** STUB DISCLOSURE (each documented) ***
#   S1. sess_A/B/C are emulator-allocated zeroed blobs (0x2000 each), NOT the
#       real device sessions. Their *internal* fields (chip dims, the matcher
#       vtable in sess_C+8/+0x60/+0xc0, the finger-list at sess_B+0x18) are NOT
#       what the real init builds. THEREFORE: any fault that occurs INSIDE or
#       AFTER a `blr *(sess_C+off)` matcher-vtable call, or while walking the
#       fabricated finger-list, is a STUB artifact and is NOT reported. Only a
#       fault in the PARAM REDZONE (0xbbbb*) on attacker input bytes, occurring
#       in the handler's own length/offset parse BEFORE any session-vtable call,
#       counts as a real OOB.
#   S2. We point sess_C+8 / +0x60 / +0xc0 (the matcher vtable slots the algo
#       handlers blr) at a `mov w0,wzr;ret` gadget so the handler RETURNS cleanly
#       past the opaque matcher instead of jumping to a fabricated address. This
#       lets the handler's own input parse run; it does NOT model the matcher.
#
# Op selector = record byte[0]:
#   'P' sensor_init (real install attempt; FAULTS — kept only to demonstrate)
#   'D'/'I' sensor detect/pre_detect
#   'C' sensor capture_image (mod 0x3EA sub 3)
#   'A' algo (mod 0x3E9), sub = body[0]
#   'F' fpcore (mod 0x3E8), sub = body[0]
#   'R' algo result-data (mod 0x3E9 sub 0x18)
# Explicit pins: G_MODULE / G_SUB. Length driver: G_LENOFF / G_LENVAL.

GP_CMD = int(os.environ.get("G_CMD", "0x1234"), 0)     # != 0x1000 -> modules dispatcher
PTYPES = int(os.environ.get("G_PT", "0x537"), 0)       # slot0 INOUT; mismatch only logs
INSZ   = int(os.environ.get("G_INSZ", "0x2000"), 0)    # large enough for result-data (>=0x1024)
OUTSZ  = int(os.environ.get("G_OUTSZ", "0x1000"), 0)
G_MODULE = os.environ.get("G_MODULE")
G_SUB    = os.environ.get("G_SUB")
G_LENOFF = int(os.environ.get("G_LENOFF", "-1"), 0)
G_LENVAL = int(os.environ.get("G_LENVAL", "0x10000"), 0) & 0xFFFFFFFF
G_PRIME  = os.environ.get("G_PRIME", "1") == "1"       # install stub sessions in init_fuzz

# ---- global slot addresses (capstone-derived, BSS) ----
SLOT_B = 0xC0C308   # *(0xC006F0)
SLOT_A = 0xC0C338   # *(0xC006F8)
SLOT_C = 0xC0C328   # *(0xC00700)

SEL = {
    0x50: (0x3EA, 2),    # 'P' prime sensor_init (real, faults)
    0x44: (0x3EA, 1),    # 'D' detect
    0x49: (0x3EA, 0),    # 'I' pre_detect
    0x43: (0x3EA, 3),    # 'C' capture_image
    0x52: (0x3E9, 0x18), # 'R' algo result-data
}

_GADGET = [None]  # filled in init_fuzz: VA of a `mov w0,wzr; ret`

def init_fuzz(ta_mgr, sid):
    """Stand in for gf_sensor_init (which faults on unmodeled sensor cfg/SPI):
    allocate + install zeroed stub session objects into the 3 BSS slots, and
    neutralise the matcher vtable so the algo handlers' own input parse runs."""
    ql = ta_mgr.ql
    if not G_PRIME:
        print("[goodix-prime] G_PRIME=0 -> sessions left NULL (baseline)")
        return
    def alloc(n, tag):
        p = ql.mem.map_anywhere(max(n, 0x2000), minaddr=0xcccc0000, perms=3, info=tag)
        ql.mem.write(p, b"\x00" * max(n, 0x2000))
        return p
    sess_A = alloc(0x2000, "goodix_sessA")
    sess_B = alloc(0x2000, "goodix_sessB")
    sess_C = alloc(0x2000, "goodix_sessC")
    # find a `mov w0,#0; ret` gadget VA (00 00 80 52 c0 03 5f d6) in the exec image,
    # to neutralise the opaque matcher vtable (STUB S2).
    base = 0x555555554000
    try:
        # scan the TA exec segment for the gadget bytes
        data = ql.mem.read(base + 0xd8000, 0x6a0000)
        idx = bytes(data).find(bytes.fromhex("0000805200035fd6"))
        gadget = (base + 0xd8000 + idx) if idx >= 0 else (base + 0xe5030)  # 0xe5030 = mov w0,wzr;ret
    except Exception:
        gadget = base + 0xe5030
    _GADGET[0] = gadget
    # neutralise the matcher vtable slots the algo handlers blr (+8, +0x60, +0xc0)
    for off in (0x8, 0x18, 0x20, 0x38, 0x60, 0xc0):
        ql.mem.write_ptr(sess_C + off, gadget)
        ql.mem.write_ptr(sess_A + off, gadget)
        ql.mem.write_ptr(sess_B + off, gadget)
    # install the session pointers into the BSS slots (guest VA = base + slot)
    ql.mem.write_ptr(base + SLOT_A, sess_A)
    ql.mem.write_ptr(base + SLOT_B, sess_B)
    ql.mem.write_ptr(base + SLOT_C, sess_C)
    print(f"[goodix-prime] sess_A={sess_A:#x}->slotA  sess_B={sess_B:#x}->slotB  "
          f"sess_C={sess_C:#x}->slotC  gadget={gadget:#x}")

def _build(module_id, sub_cmd, insz, payload=b"", lenoff=-1, lenval=0):
    buf = bytearray(insz)
    struct.pack_into("<I", buf, 0, 0)
    struct.pack_into("<I", buf, 4, module_id & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 8, sub_cmd & 0xFFFFFFFF)
    if payload:
        n = min(len(payload), insz - 0x1C)
        buf[0x1C:0x1C+n] = payload[:n]
    if 0 <= lenoff and lenoff + 4 <= insz:
        struct.pack_into("<I", buf, lenoff, lenval & 0xFFFFFFFF)
    return bytes(buf)

def _decode(input: bytes):
    if G_MODULE is not None:
        module_id = int(G_MODULE, 0)
        sub_cmd = int(G_SUB, 0) if G_SUB is not None else 0
        return module_id, sub_cmd, INSZ, input, G_LENOFF, G_LENVAL
    if len(input) < 1:
        return 0x3E9, 0x18, INSZ, b"", G_LENOFF, G_LENVAL
    sel = input[0]; body = input[1:]
    if sel in SEL:
        m, s = SEL[sel]
        lv = struct.unpack_from("<I", body, 0)[0] if (len(body) >= 4 and G_LENOFF >= 0) else G_LENVAL
        return m, s, INSZ, body, G_LENOFF, lv
    if sel == 0x41:  # 'A' algo
        return 0x3E9, (body[0] if body else 0), INSZ, body[1:], G_LENOFF, G_LENVAL
    if sel == 0x46:  # 'F' fpcore
        return 0x3E8, (body[0] if body else 0), INSZ, body[1:], G_LENOFF, G_LENVAL
    return 0x3E9, 0x18, INSZ, body, G_LENOFF, G_LENVAL

def place_input_callback(ql: Qiling, input: bytes, idx: int):
    module_id, sub_cmd, insz, payload, lenoff, lenval = _decode(input)
    buf = _build(module_id, sub_cmd, insz, payload, lenoff, lenval)
    print(f"[goodix-mc op{idx}] mod={module_id:#x} sub={sub_cmd:#x} insz={insz:#x} "
          f"paylen={len(payload):#x} lenoff={lenoff} lenval={lenval:#x}")
    command_params = [
        MemRefParam(buf, insz),
        ValueParam(insz, 0),
        MemRefParam(bytes(OUTSZ), OUTSZ),
        NoneParam(),
    ]
    setup_params_fuzz(ql, GP_CMD, PTYPES, command_params)
    return True
