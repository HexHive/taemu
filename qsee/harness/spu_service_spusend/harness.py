from .params import *
from qiling import Qiling
import struct, os
from . import qsee_api   # to publish SPU_RESP for qsee_spcom_client_send_message_sync

# === spu_service method-9 SPU response-trust test (Finding B clamp) =========
# Target: Xiaomi houji spu_service.ta. Drive method 9 (send key to SPU,
# sub-cmd 0x51a) whose path reaches the SPU response copy-back at 0x24ac:
#   0x2530 bl 0x3010      ; transact; [sp+0xc]=resp_len, [sp+0x10]=resp_ptr
#   0x255c ldr w3,[sp+0xc]; resp_len (SPU/peer-controlled)
#   0x2560 cmp x3, x20    ; x20 = out_cap = param1.size  (NW-supplied)
#   0x2564 b.ls 0x2584    ; copy ONLY if resp_len <= out_cap, else "too short"
#   0x2590 bl 0x3f94      ; memcpy(out_ptr, src, min(out_cap,..))  [clamped]
# There is a SECOND clamp inside 0x3010 at 0x3088 ("Response is too long":
# resp_len <= req_cap - payload). We dynamically exercise the response-trust
# copy: publish an SPU response with a HUGE length and a TIGHT out buffer ending
# at a guard page. If either clamp holds, NO copy past the buffer -> no fault
# (bounded). If the length were trusted unbounded, the memcpy would overflow the
# out buffer into the guard page -> UC_ERR_WRITE_UNMAPPED (a real bug).
#
# Method 9 ABI (dispatcher 0x558): w1=9, w3==0x11, x2=ObjectArg[]:
#   slot0 {ptr=req(param0.ptr), size=req_len(param0.size)}   (the SPU cmd buf)
#   slot1 {ptr=out(param1.ptr), size=out_cap(param1.size)}   (response dst)
# 0x3124 spu_km_verify_cmd_hdr(req, req_len, expected=0x51a) requires req[0..3]
# big-endian == 0x0000051a and req_len>=4.
#
# Shared-buffer globals (set by method 6 normally) are pre-stamped here so the
# 0x2144 gate passes without running the multi-method registration:
#   [ta+0x11068]=shared_buf_ptr, [ta+0x11070]=shared_buf_size, [ta+0x110a8]=1.

AFL_EXIT = 0x13370
METHOD_SENDKEY = 9
COUNTS_0x11   = 0x11
EXPECT_CMD_BE = 0x0000051a   # method 9 expects BE u32 0x51a in req[0..3]

ARG_BASE   = 0x55000000
REQ_BASE   = 0x55100000      # SPU command buffer (param0)
SHARED_BASE= 0x55300000      # the SPU shared buffer (globals point here)
SHARED_SIZE= 0x4000

# out buffer (param1) placed at the END of a mapped page; next page UNMAPPED.
OUT_CELL   = 0x55200000
PAGE       = 0x1000

# default: huge SPU response length to test the clamp; small out_cap.
OUT_CAP    = int(os.environ.get("SPU_OUTCAP", str(0x40)), 0) & 0xFFFFFFFF
RESP_LEN   = int(os.environ.get("SPU_RESPLEN", str(0x2000)), 0) & 0xFFFFFFFF


def _out_addr(cap):
    return OUT_CELL + PAGE - cap     # ends exactly at the guard page


def init_fuzz(emu, sid):
    ql = emu.ql
    for base, size, name in ((ARG_BASE, PAGE, "args"), (REQ_BASE, PAGE, "req"),
                             (OUT_CELL, PAGE, "outcell"), (SHARED_BASE, SHARED_SIZE, "shared")):
        try:
            ql.mem.map(base, size, info=f"[spu9] {name}")
        except Exception as e:
            ql.log.warning(f"[spu9] map {name}: {e}")
    # NOTE: we deliberately map ONLY OUT_CELL's first page -> the page after is a
    # guard so a too-long copy faults.
    print(f"[spu9] init: args@{hex(ARG_BASE)} req@{hex(REQ_BASE)} out_cell@{hex(OUT_CELL)} shared@{hex(SHARED_BASE)}")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives (resp_len, out_cap). resp_len > out_cap is the interesting case
    # (must be rejected by the clamp). out_cap default small.
    resp_len = RESP_LEN
    out_cap = OUT_CAP
    if "SPU_RESPLEN" not in os.environ and len(input) >= 4:
        resp_len = struct.unpack_from("<I", input, 0)[0] % (0x4000 + 1)
    if "SPU_OUTCAP" not in os.environ and len(input) >= 8:
        out_cap = (struct.unpack_from("<I", input, 4)[0] % PAGE) or 0x40

    out_ptr = _out_addr(out_cap)

    # pre-stamp the shared-buffer globals so 0x2144 passes
    ta = ql.mem.get_lib_base("spu_service.ta")
    try:
        ql.mem.write(ta + 0x11068, struct.pack("<Q", SHARED_BASE))   # base
        ql.mem.write(ta + 0x11070, struct.pack("<Q", SHARED_SIZE))   # size
        ql.mem.write(ta + 0x110a8, struct.pack("<I", 1))             # init flag
    except Exception as e:
        ql.log.warning(f"[spu9] stamp globals: {e}")

    # SPU command request: the verify_hdr assembles req[0..3] LITTLE-endian
    # (b0|b1<<8|b2<<16|b3<<24) and compares to 0x51a -> bytes 1a 05 00 00.
    req = bytearray(0x100)
    struct.pack_into("<I", req, 0, EXPECT_CMD_BE)
    ql.mem.write(REQ_BASE, bytes(req))
    REQ_LEN = 0x40

    # the SPU response the stub will emit into the shared buffer: a 'succ' magic
    # ("succ" little-endian = 63 63 75 73) at +4 and a HUGE length at +8, then
    # filler. The TA frames it; resp_len reaches the 0x2560 clamp.
    resp = bytearray(0x200)
    struct.pack_into("<I", resp, 0, 0)                 # +0 status/hdr
    struct.pack_into("<I", resp, 4, 0x73756363)        # +4 'succ'
    struct.pack_into("<I", resp, 8, resp_len)          # +8 response length (attacker)
    for i in range(0x10, 0x200):
        resp[i] = 0x43
    qsee_api.SPU_RESP["bytes"] = bytes(resp)

    # ObjectArg[]: slot0 = {REQ_BASE, REQ_LEN}, slot1 = {out_ptr, out_cap}
    a = bytearray(0x80)
    struct.pack_into("<Q", a, 0x00, REQ_BASE)
    struct.pack_into("<Q", a, 0x08, REQ_LEN)
    struct.pack_into("<Q", a, 0x10, out_ptr)
    struct.pack_into("<Q", a, 0x18, out_cap)
    ql.mem.write(ARG_BASE, bytes(a))
    # fill out buffer with zero (so an in-bounds copy is observable, OOB faults)
    ql.mem.write(out_ptr, b"\x00" * out_cap)

    setup_params_fuzz(ql, METHOD_SENDKEY, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    ql.arch.regs.x0 = ARG_BASE + 0x800     # ctx (refcount), away from args
    ql.arch.regs.x1 = METHOD_SENDKEY
    ql.arch.regs.x2 = ARG_BASE
    ql.arch.regs.x3 = COUNTS_0x11
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[spu9] method=9 resp_len={resp_len:#x} out_cap={out_cap:#x} out_ptr={out_ptr:#x} "
          f"(guard@{OUT_CELL+PAGE:#x}); clamp at 0x2560 must reject resp_len>out_cap")
    return True
