#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === FPC optical fingerprint TA (f13010e0) structure-aware harness =========
# (Wave-2 F4) RE doc: RE/xiaomi_mitee/mitee_widevine.md (FPC, NOT Widevine).
#
# REAL entry gate (.ta TA_InvokeCommandEntryPoint @0x242160, re-derived; the .ta
# differs from the RE-doc .elf @0x32ABA8 but the staging json offsets are correct
# for the .ta):
#   w2 (paramTypes) == 7  -> p0 = MEMREF_INOUT, p1/2/3 = NONE  (cmp w2,#7; b.ne @0x24217c)
#   GP commandID (w1) == 0x105 -> fpc_ta_route_command @0x23a230   (cmp w20,#0x105 @0x242298)
#     (cmd 0x1000 = CMD_GET_PAY_IDS; everything else "Unknown")
#   Router call: x0 = param0.buf, w1 = param0.size - 4   (@0x242340: sub w1,size,#4).
#
# ROUTER (fpc_ta_route_command @0x23a230):
#   - requires g_ta_router_initialized (set by lazy init on first invoke).
#   - len (= size-4) must be > 0x17  (cmp w1,#0x17; b.ls fail) -> size >= 0x1C.
#   - target_id = req->u32[0] (buf[0]); target_id==12 -> SUICIDE (brk #1) [DoS, excluded].
#   - walks 11 descriptors; matched -> handler(x0=buf).
#   - target_id==5 (hw_auth) & subcmd(req->u32[1]) in {3,4,5}: size guard
#       req->u32[6] (buf+0x18) + 0x20 must be <= len AND not wrap.
#   Handlers (target_id -> handler): 1=common, 2=device, 3=algo(@0x31E858 in .elf),
#     5=hw_auth, 6=db_blob (AES-GCM template DB), 8=calibration (CVE-2020-0423-class
#     chunk parsers: data_decrypt/receive_common), 9=sensortest, 10=kpi, 256=ifaa,
#     257=wechat.
#
# Frame (param0, MEMREF_INOUT): [u32 target_id][u32 subcmd][u32 ...][body]
# The fuzz `input` supplies target_id(byte0->valid id), subcmd, and the body.
# Targets with the richest attacker-controlled length/offset parsing (per RE doc
# attack-surface notes) are 8 (calibration), 6 (db_blob), 5 (hw_auth), 3 (algo).

PTYPES = 0x7
GP_CMD = 0x105
BUFSZ  = 0x800     # >= 0x1C; generous so handlers' interior reads land in-buffer

# PIE load base (constant in this emulator) + the two lazy-init gate globals.
# The real lazy init (sub_29d920(0x3200000) + sub_23a018) faults on an unmodeled
# Zircon resource at .ta+0x293e58 (`ldr x0,[x0]` on a NULL singleton handle).
# To reach the router + handler PARSERS (where the OOB sinks live) we pre-set the
# two init flags so the entry skips lazy-init and the router passes its gate:
#   g_fpcta_initialized      @ .ta off 0x2dc340  (entry @0x242220 ldrb [x21+0x340])
#   g_ta_router_initialized  @ .ta off 0x2dc000  (router @0x23a230 ldrb [0x2dc000])
PIE_BASE = 0x555555554000
G_FPCTA_INIT = PIE_BASE + 0x2dc340
G_ROUTER_INIT = PIE_BASE + 0x2dc000

def init_fuzz(emu, sid):
    # Bypass the unmodeled FPC-core lazy init: mark both init flags set so the
    # Invoke entry skips sub_29d920/sub_23a018 and fpc_ta_route_command's gate
    # (`ldrb [0x2dc000]; cmp #1`) passes -> dispatch reaches the 10 handlers.
    try:
        emu.ql.mem.write(G_FPCTA_INIT, b"\x01")
        emu.ql.mem.write(G_ROUTER_INIT, b"\x01")
        print(f"[F130] pre-set init flags @ {G_FPCTA_INIT:#x} / {G_ROUTER_INIT:#x}")
    except Exception as e:
        print(f"[F130] init_fuzz flag-poke failed: {e}")

# Valid target ids (exclude 12 = unauthenticated suicide/brk DoS, not mem-corruption).
TARGETS = [1, 2, 3, 5, 6, 8, 9, 10, 256, 257]

def place_input_callback(ql: Qiling, input: bytes, _: int):
    if len(input) < 1:
        return False

    pin_t = os.environ.get("F130_TARGET")
    pin_s = os.environ.get("F130_SUBCMD")

    if pin_t is not None:
        target = int(pin_t, 0)
    else:
        target = TARGETS[input[0] % len(TARGETS)]

    if pin_s is not None:
        subcmd = int(pin_s, 0)
        body = input
    else:
        subcmd = input[1] if len(input) > 1 else 0   # 0..255 sub-command space
        body = input[2:]

    # Build the request frame: [target_id][subcmd][body...]; pad to BUFSZ.
    frame = struct.pack("<II", target & 0xFFFFFFFF, subcmd & 0xFFFFFFFF) + body
    frame = frame[:BUFSZ].ljust(BUFSZ, b"\x00")

    command_params = [
        MemRefParam(frame, BUFSZ),   # param0 = request/response (redzoned)
        NoneParam(),
        NoneParam(),
        NoneParam(),
    ]
    setup_fuzz(ql, GP_CMD, PTYPES, command_params, input)
    return True
