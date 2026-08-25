from .params import *
from . import asan
from qiling import Qiling
import struct, os

# houji KeyMint deserializeCharacteristics TRACE harness (offsets repointed from
# the S928B keymint_dkmk trace diag). Drives decodeKeyBlob@0x3115c with a DKMK
# blob + redzoned 0x5f0 out-struct, and traces the houji milestone sites so we can
# see the DKMK gate, the deserializer envelope, the PURPOSE loop and the store.

RET_GADGET        = 0x250dc
DECODE_KEY_BLOB   = 0x3115c
OUT_USER_SIZE     = 0x5f0
BLOB_BASE   = 0x51000000
BLOB_SIZE   = 0x40000
OUT_MINADDR = 0x52000000

def _cbor_hdr(major, val):
    mt = major << 5
    if val < 24:       return bytes([mt | val])
    elif val < 0x100:  return bytes([mt | 24, val])
    elif val < 0x10000:return bytes([mt | 25]) + struct.pack(">H", val)
    elif val < 0x100000000: return bytes([mt | 26]) + struct.pack(">I", val)
    else:              return bytes([mt | 27]) + struct.pack(">Q", val)
def cbor_uint(v): return _cbor_hdr(0, v)
def cbor_bstr(b): return _cbor_hdr(2, len(b)) + b
def cbor_arr(n):  return _cbor_hdr(4, n)
def cbor_map(n):  return _cbor_hdr(5, n)
DKMK = 0x4b4d4b44
_OUT = {}; _BASE = {}

def _frame(chars: bytes) -> bytes:
    return (cbor_arr(4) + cbor_uint(DKMK) + cbor_uint(0) + cbor_uint(0) + cbor_bstr(chars))

def _default_chars():
    cnt = int(os.environ.get("KM_COUNT", "12"), 0)
    elem = int(os.environ.get("KM_ELEM", "374"), 0)
    cm = bytearray()
    cm += cbor_map(2)
    cm += cbor_uint(1); cm += cbor_map(1); cm += cbor_uint(0x20000001); cm += cbor_arr(cnt)
    for _ in range(cnt): cm += cbor_uint(elem)
    cm += cbor_uint(0); cm += cbor_map(0)
    return bytes(cm)

def init_fuzz(emu, sid):
    ql = emu.ql
    try: ql.mem.map(BLOB_BASE, BLOB_SIZE, info="[kmt] blob")
    except Exception as e: ql.log.warning(f"[kmt] map blob: {e}")
    user, region, real = asan.install_param_redzones(ql, emu, b"\x00" * OUT_USER_SIZE, OUT_USER_SIZE, OUT_MINADDR)
    _OUT["user"], _OUT["region"], _OUT["real"] = user, region, real
    try: base = ql.mem.get_lib_base("keymint_houji.ta")
    except Exception: base = 0x555555554000
    _BASE["base"] = base; _BASE["ret"] = base + RET_GADGET

    st = {"stores": 0, "decodes": 0}
    def on_code(q, addr, size):
        rel = addr - base
        r = q.arch.regs
        if rel == 0x3115c:
            print(f"[kmt] decodeKeyBlob enter x0={r.x0:#x} x1={r.x1:#x} x2(out)={r.x2:#x}", flush=True)
        elif rel == 0x3121c:   # cmp x4,DKMK
            print(f"[kmt] DKMK gate @0x3121c: [blob]=x4={r.x4:#x} vs 0x4b4d4b44 -> {'MATCH' if r.x4==0x4b4d4b44 else 'MISS->decrypt'}", flush=True)
        elif rel == 0x3123c:   # bl deserializeCharacteristics
            print(f"[kmt] -> bl deserializeCharacteristics@0x308a0 x0={r.x0:#x} x1={r.x1:#x} x2(obj)={r.x2:#x}", flush=True)
        elif rel == 0x308a0:
            print(f"[kmt] === deserializeCharacteristics enter x0(chars)={r.x0:#x} x1(len)={r.x1:#x} x2(obj)={r.x2:#x}", flush=True)
        elif rel == 0x30b04:
            cnt = int.from_bytes(q.mem.read(r.sp+0x10,2),'little')
            print(f"[kmt] *** PURPOSE loop#1 @0x30b04 reached; inner count [sp+0x10]={cnt}", flush=True)
        elif rel == 0x30b38:   # store str w9,[x8,#0x18]
            st["stores"] += 1
            idx = int.from_bytes(q.mem.read(r.x19+0x30,8),'little')
            tgt = (r.x8 + 0x18) & 0xffffffffffffffff
            print(f"[kmt] *** STORE#{st['stores']} @0x30b38 dst={tgt:#x} (x8+0x18) idx_now@+0x30={idx} value={r.x9 & 0xffffffff:#x} obj={r.x19:#x} redzone_after={_OUT['user']+OUT_USER_SIZE:#x}", flush=True)
        elif rel == 0x31140:   # tag-miss error in deserializer
            print(f"[kmt] !!! tag-miss error @0x31140 (unknown tag)", flush=True)
        elif rel in (0x310e4,):  # deserializer top-level error return
            print(f"[kmt] !!! deser error-return @0x310e4 w0={r.x0 & 0xffffffff:#x}", flush=True)
        elif rel == 0x31398:
            print(f"[kmt] !!! decodeKeyBlob error tail @0x31398", flush=True)
    ql.hook_code(on_code)
    print(f"[kmt] init base={hex(base)} ret@{hex(_BASE['ret'])} out@{hex(user)} redzone_after@{hex(user+OUT_USER_SIZE)}", flush=True)

def place_input_callback(ql: Qiling, input: bytes, _: int):
    raw = os.environ.get("KM_RAWBLOB", "")
    if raw: blob = bytes.fromhex(raw)
    else:
        chars_hex = os.environ.get("KM_CHARS", "")
        chars = bytes.fromhex(chars_hex) if chars_hex else _default_chars()
        blob = _frame(chars)
    if len(blob) > BLOB_SIZE: blob = blob[:BLOB_SIZE]
    ql.mem.write(BLOB_BASE, blob)
    ql.mem.write(_OUT["user"], b"\x00" * OUT_USER_SIZE)
    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])
    ql.arch.regs.x0 = BLOB_BASE; ql.arch.regs.x1 = len(blob)
    ql.arch.regs.x2 = _OUT["user"]; ql.arch.regs.x3 = 0
    ql.arch.regs.x30 = _BASE["ret"]
    print(f"[kmt] decodeKeyBlob(blob={len(blob)}B = {blob.hex()})", flush=True)
    return True
