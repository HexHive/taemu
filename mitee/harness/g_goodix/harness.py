from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === goodix_fp (a734eed9) structure-aware harness — F8 ==================
# Target: klee Goodix G3T FoD matcher a734eed9 (12.5 MB), sha c48e5f73….
#
# REAL gate (TA_InvokeCommandEntryPoint @0xEE008, capstone-verified):
#   w20=cmd, x21=sessctx, x19=params.  cmp paramTypes,#0x537 ONLY LOGS (no abort).
#   real gate = TEE_CheckMemoryAccessRights(7, params[0].ptr, params[0].size) @0xee058.
#   cmd==0x1000 -> 188-B info blob ; else -> gf_modules_cmd_entry_point @0xDD030
#     with (x0=params[0].ptr, w1=params[0].size); result -> params[0]+0x14.
#
# modules dispatcher @0xDD030: buf_len>0x1B (>=28) BEFORE any deref;
#   module_id = *(u32*)(input+4); linear-compare 5 modules; call module+0x10(input,len).
#   module table:  0x3E8 fpcore(0xD8610->sub-switch 0xDC520) | 0x3E9 algo(0xDE188)
#                  0x3EA sensor(0xDFE78) | 0x3EB product(0xDE658) | 0x3F4 (0x7462D8)
#   fpcore sub-switch @0xDC520: buf_len>0x1B ; sub_cmd=*(u32*)(input+8) ; <=0x12.
#
# Frame: param0 = MEMREF (INOUT, the input buffer; result written to +0x14 so must be RW).
#   input layout:  [u32 @+0 hdr][u32 module_id @+4][u32 sub_cmd @+8][... payload ...]
#   paramTypes 0x537 (slot0 INOUT(7), slot1 VALUE(3), slot2 MEMREF_IN(5)). Mismatch only
#   logs; we set the honest 0x537 plus a 2nd MEMREF (param2) the algo/result path may use.
#
# Modes (env):
#   G_CMD    (default 0x1000) = GP cmd_id. 0x1000 = info-blob smoke test.
#            Any other value (e.g. 0x1234) routes to the modules dispatcher.
#   G_MODULE (default 0x3E8)  = module_id placed at input+4.
#   G_SUB    (default 0x1)    = sub_cmd placed at input+8.
#   G_INSZ   (default 0x800)  = param0 buffer size (must be > 0x1B).
#   G_OUTSZ  (default 0x1000) = param2 secondary buffer size.
#   G_LENOFF (default -1)     = if >=0, place a u32 length field at input+G_LENOFF
#                              (drive the embedded-length OOB surface). value=G_LENVAL.
#   G_LENVAL (default 0x10000)
#
# AFL: when no G_* pin is set for the mutated field, the first input bytes drive
#   sub_cmd (input[0:4]) and the embedded length field (input[4:8]).

G_CMD    = int(os.environ.get("G_CMD",    "0x1000"), 0)
G_MODULE = int(os.environ.get("G_MODULE", "0x3E8"),  0) & 0xFFFFFFFF
G_SUB    = int(os.environ.get("G_SUB",    "0x1"),    0) & 0xFFFFFFFF
G_INSZ   = int(os.environ.get("G_INSZ",   "0x800"),  0)
G_OUTSZ  = int(os.environ.get("G_OUTSZ",  "0x1000"), 0)
G_LENOFF = int(os.environ.get("G_LENOFF", "-1"),     0)
G_LENVAL = int(os.environ.get("G_LENVAL", "0x10000"),0) & 0xFFFFFFFF
PTYPES   = int(os.environ.get("G_PT",     "0x537"),  0)

def _build(module_id, sub_cmd, lenoff, lenval, payload=b""):
    buf = bytearray(G_INSZ)
    struct.pack_into("<I", buf, 0, 0)            # hdr u32 (unused by dispatch)
    struct.pack_into("<I", buf, 4, module_id)    # module_id
    struct.pack_into("<I", buf, 8, sub_cmd)      # sub_cmd
    # leave +0xC..+0x1C as scratch (result lands at +0x14)
    if payload:
        buf[0x1C:0x1C+len(payload)] = payload[:G_INSZ-0x1C]
    if lenoff is not None and lenoff >= 0 and lenoff+4 <= G_INSZ:
        struct.pack_into("<I", buf, lenoff, lenval)
    return bytes(buf)

def place_input_callback(ql: Qiling, input: bytes, _: int):
    module_id = G_MODULE
    sub_cmd   = G_SUB
    lenoff    = G_LENOFF if G_LENOFF >= 0 else None
    lenval    = G_LENVAL
    # AFL exploration when not pinned
    if len(input) >= 8:
        if "G_SUB" not in os.environ:
            sub_cmd = struct.unpack_from("<I", input, 0)[0] % 0x13   # 0..0x12
        if "G_LENVAL" not in os.environ and lenoff is not None:
            lenval = struct.unpack_from("<I", input, 4)[0]

    buf = _build(module_id, sub_cmd, lenoff, lenval, payload=input[8:] if len(input) > 8 else b"")
    print(f"[G] cmd={G_CMD:#x} module={module_id:#x} sub={sub_cmd:#x} "
          f"insz={G_INSZ:#x} lenoff={lenoff} lenval={lenval:#x} pt={PTYPES:#x}")
    command_params = [
        MemRefParam(buf, G_INSZ),             # param0 INOUT (input; result @+0x14)
        ValueParam(G_INSZ, 0),                # param1 VALUE (honest 0x537 slot1)
        MemRefParam(bytes(G_OUTSZ), G_OUTSZ), # param2 MEMREF (secondary out, redzoned)
        NoneParam(),
    ]
    setup_params_fuzz(ql, G_CMD, PTYPES, command_params)
    return True
