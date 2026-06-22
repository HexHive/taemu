from .params import *
from . import asan
from qiling import Qiling
import struct, os

# === KeyMint deserializeCharacteristics CBOR-envelope TRACE harness =========
# Same staging as keymint_dkmk (drives decodeKeyBlob@0x30740 with a DKMK blob +
# redzoned 0x5f0 out-struct) BUT with deep instrumentation of the bespoke CBOR
# parser so we can SEE exactly how a candidate characteristics blob is parsed and
# where it diverges from what deserializeCharacteristics@0x2fe84 expects.
#
# We hook (ta-relative):
#   0x46634  CBOR "decode next item" wrapper (x0=ctx, x1=item-out). On RETURN we
#            dump ctx cursor [ctx+8]/end[ctx+0x10] and the item fields.
#   0x47638  map-open ; 0x476c0 map-enter(w1) ; 0x47544 close ; 0x47770 dec-depth
#   0x2fe84/0x300e4/0x3011c/0x306c4 the milestone sites.
# Feed the characteristics bytes with KM_RAWBLOB (hex of the *whole* DKMK blob)
# or KM_CHARS (hex of just the characteristics member; we wrap it in the frame).

RET_GADGET        = 0xd7f8
DECODE_KEY_BLOB   = 0x30740
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

_OUT = {}
_BASE = {}


def _frame(chars: bytes) -> bytes:
    blob = bytearray()
    blob += cbor_arr(4)
    blob += cbor_uint(DKMK)
    blob += cbor_uint(0)
    blob += cbor_uint(0)
    blob += cbor_bstr(chars)
    return bytes(blob)


def _default_chars():
    # default candidate: outer map{1} -> HW map{1} -> {PURPOSE: array(count)}
    # (this is the shape we are validating; trace shows where it breaks)
    cnt = int(os.environ.get("KM_COUNT", "5"), 0)
    purpose = bytearray()
    purpose += cbor_map(1)
    purpose += cbor_uint(0x20000001)
    purpose += cbor_arr(cnt)
    for _ in range(cnt):
        purpose += cbor_uint(1)
    outer = bytearray()
    outer += cbor_map(1)
    outer += bytes(purpose)
    return bytes(outer)


def init_fuzz(emu, sid):
    ql = emu.ql
    try:
        ql.mem.map(BLOB_BASE, BLOB_SIZE, info="[kmt] blob")
    except Exception as e:
        ql.log.warning(f"[kmt] map blob: {e}")
    user, region, real = asan.install_param_redzones(ql, emu, b"\x00" * OUT_USER_SIZE,
                                                      OUT_USER_SIZE, OUT_MINADDR)
    _OUT["user"], _OUT["region"], _OUT["real"] = user, region, real
    try:
        base = ql.mem.get_lib_base("keymint.ta")
    except Exception:
        base = 0x555555554000
    _BASE["base"] = base
    _BASE["ret"] = base + RET_GADGET

    # ---- instrumentation ---------------------------------------------------
    DECODE_NEXT = base + 0x46634
    state = {"pending_item": None, "n": 0}

    def dump_ctx(tag, ctx):
        try:
            cur = int.from_bytes(ql.mem.read(ctx + 8, 8), "little")
            end = int.from_bytes(ql.mem.read(ctx + 0x10, 8), "little")
            magic = int.from_bytes(ql.mem.read(ctx + 0x18, 2), "little")
            depth = int.from_bytes(ql.mem.read(ctx + 0x240, 4), "little")
            errf = int.from_bytes(ql.mem.read(ctx + 0x40, 4), "little")
            # item lives at ctx+8 in deserializeCharacteristics ('add x20,x19,#8')
            it = ql.mem.read(ctx + 8, 0x40)
            print(f"[kmt] {tag}: ctx={ctx:#x} cur={cur:#x} end={end:#x} "
                  f"left={end-cur if end>=cur else -1} magic={magic:#x} depth={depth} err={errf} "
                  f"item[0..0x10]={it[:0x10].hex()} item.kind={it[0]:#x} item.mtype={it[2]:#x} "
                  f"item@8={int.from_bytes(it[8:0x10],'little'):#x} "
                  f"item@0x18={int.from_bytes(it[0x18:0x20],'little'):#x} "
                  f"item@0x28={int.from_bytes(it[0x28:0x30],'little'):#x}", flush=True)
        except Exception as e:
            print(f"[kmt] {tag}: dump fail {e}", flush=True)

    def on_code(q, addr, size):
        rel = addr - base
        r = q.arch.regs
        if rel == 0x46634:
            # entry: x0=ctx, x1=item-out
            state["pending_item"] = (r.x0, r.x1)
            state["n"] += 1
            if state["n"] < 200:
                print(f"[kmt] >>> decode_next #{state['n']} ctx={r.x0:#x} item_out={r.x1:#x} "
                      f"(called from lr={r.x30-base:#x})", flush=True)
        elif rel == 0x2fe84:
            print(f"[kmt] === deserializeCharacteristics x0(chars)={r.x0:#x} x1(len)={r.x1:#x} "
                  f"x2(obj)={r.x2:#x}", flush=True)
            try:
                cb = q.mem.read(r.x0, min(r.x1, 64))
                print(f"[kmt]     chars bytes = {cb.hex()}", flush=True)
            except Exception:
                pass
        elif rel == 0x2fefc:
            print(f"[kmt] -> call map-open(0x47638) ctx={r.x0:#x}", flush=True); dump_ctx("pre-open", r.x0)
        elif rel == 0x2ff00:
            dump_ctx("post-open", r.x0 if False else (r.x0))  # x0 clobbered; use saved
        elif rel == 0x2ff18:
            print(f"[kmt] post map-open: w0={r.x0 & 1}", flush=True)
        elif rel == 0x2ff24:
            print(f"[kmt] HW loopA count [sp+0x50]={int.from_bytes(q.mem.read(r.sp+0x50,2),'little')}", flush=True)
        elif rel == 0x300e4:
            print(f"[kmt] *** PURPOSE loop#1 @0x300e4 reached; inner count [sp+0x10]="
                  f"{int.from_bytes(q.mem.read(r.sp+0x10,2),'little')}", flush=True)
        elif rel == 0x3011c:
            idx = int.from_bytes(q.mem.read(r.x19+0x30,8),'little')
            print(f"[kmt] *** STORE @0x3011c x8={r.x8:#x} (struct+idx*4+0x18) idx_now@+0x30={idx} "
                  f"value={r.x9 & 0xffffffff:#x}", flush=True)
        elif rel == 0x304ec:
            print(f"[kmt] SW loopB count [sp+0x50]={int.from_bytes(q.mem.read(r.sp+0x50,2),'little')}", flush=True)
        elif rel == 0x306c4 or rel == 0x3069c or rel == 0x306a0:
            print(f"[kmt] !!! ERROR log @{rel:#x} w3(line)={r.x3} w4(val)={r.x4}", flush=True)
        elif rel == 0x30708:
            print(f"[kmt] +++ SUCCESS path @0x30708 (status 0)", flush=True)

    # hook return of decode_next via a code hook at the retab site 0x46738
    def on_decode_ret(q, addr, size):
        rel = addr - base
        if rel == 0x46738 and state["pending_item"]:
            ctx, item = state["pending_item"]
            if state["n"] < 200:
                dump_ctx(f"decode_next #{state['n']} RET w0={q.arch.regs.x0}", ctx)

    # --- inner decoder 0x467f0 trace: pin byte -> kind mapping --------------
    inner = {"stack": []}
    def on_inner(q, addr, size):
        rel = addr - base
        r = q.arch.regs
        if rel == 0x467f0:
            # x0=stream-reader-ctx, x1=item-out, w2=flag
            inner["stack"].append((r.x0, r.x1, r.x2))
        elif rel == 0x46838:  # right after reading the head byte (0x46834 bl 0x486f4)
            pass
        elif rel == 0x46848:  # w23=major, w24=addl computed
            if len(inner["stack"]) and state["n"] < 250:
                print(f"[kmt-inner] head byte parsed: CBOR major={r.x23:#x} addl={r.x24:#x}", flush=True)
        elif rel == 0x468dc:  # retab of 467f0 (success epilogue)
            if inner["stack"]:
                ctx, item, flag = inner["stack"][-1]
                try:
                    it = q.mem.read(item, 0x20)
                    print(f"[kmt-inner] 467f0 RET(0x468dc) w0={r.x0}: item={item:#x} kind={it[0]:#x} "
                          f"mtype={it[2]:#x} val@8={int.from_bytes(it[8:0x10],'little'):#x} "
                          f"raw={it[:0x10].hex()}", flush=True)
                    inner["stack"].pop()
                except Exception:
                    pass
    ql.hook_code(on_inner)

    # --- map-open(0x47638) and map-enter(0x476c0) internal check probes ----
    def on_envelope(q, addr, size):
        rel = addr - base
        r = q.arch.regs
        if rel == 0x47678:    # map-open: ldrb w8,[x20]; cmp #5 (x20=ctx+8=item)
            print(f"[kmt-env] map-OPEN check: item.kind=[{r.x20:#x}]={q.mem.read(r.x20,1)[0]:#x} (need 5)", flush=True)
        elif rel == 0x47688:  # map-open success (w0=1)
            print(f"[kmt-env] map-OPEN OK", flush=True)
        elif rel == 0x476a4:  # map-open fail
            print(f"[kmt-env] map-OPEN FAIL", flush=True)
        elif rel == 0x476f8:  # map-enter: about to decode next, x21=ctx+8
            cur=int.from_bytes(q.mem.read(r.x19+8,8),'little'); end=int.from_bytes(q.mem.read(r.x19+0x10,8),'little')
            print(f"[kmt-env] map-ENTER w1(arg)={r.x1:#x} ctx={r.x19:#x} cur={cur:#x} end={end:#x}", flush=True)
        elif rel == 0x47700:  # after decode bl 0x46634 -> w0
            print(f"[kmt-env] map-ENTER decode w0={r.x0} (0=ok)", flush=True)
        elif rel == 0x47704:
            pass
        elif rel == 0x47708:  # enter: ldrb w8,[x21]; cmp #5
            print(f"[kmt-env] map-ENTER kind=[{r.x21:#x}]={q.mem.read(r.x21,1)[0]:#x} (need 5)", flush=True)
        elif rel == 0x47714:  # enter: ldrb w8,[x19,#0xa]; &0xfe; cmp #2
            v = q.mem.read(r.x19 + 0xa, 1)[0]
            print(f"[kmt-env] map-ENTER [ctx+0xa]={v:#x} (&0xfe must==2)", flush=True)
        elif rel == 0x47724:  # enter: ldr x8,[x19,#0x20]; cmp x20(=w1 arg)
            v = int.from_bytes(q.mem.read(r.x19 + 0x20, 8), "little")
            print(f"[kmt-env] map-ENTER [ctx+0x20]={v:#x} vs arg x20={r.x20:#x} (must be equal)", flush=True)
        elif rel == 0x47730:  # enter success
            print(f"[kmt-env] map-ENTER OK", flush=True)
        elif rel == 0x47750:  # enter fail
            print(f"[kmt-env] map-ENTER FAIL", flush=True)
    ql.hook_code(on_envelope)

    ql.hook_code(on_code)
    ql.hook_code(on_decode_ret)

    print(f"[kmt] init: base={hex(base)} decode_next@{hex(DECODE_NEXT)} "
          f"out@{hex(user)} redzone_after@{hex(user+OUT_USER_SIZE)}")


def place_input_callback(ql: Qiling, input: bytes, _: int):
    raw = os.environ.get("KM_RAWBLOB", "")
    if raw:
        blob = bytes.fromhex(raw)
    else:
        chars_hex = os.environ.get("KM_CHARS", "")
        chars = bytes.fromhex(chars_hex) if chars_hex else _default_chars()
        blob = _frame(chars)
    if len(blob) > BLOB_SIZE:
        blob = blob[:BLOB_SIZE]
    ql.mem.write(BLOB_BASE, blob)
    ql.mem.write(_OUT["user"], b"\x00" * OUT_USER_SIZE)

    setup_params_fuzz(ql, 0, 0, [NoneParam(), NoneParam(), NoneParam(), NoneParam()])
    ql.arch.regs.x0 = BLOB_BASE
    ql.arch.regs.x1 = len(blob)
    ql.arch.regs.x2 = _OUT["user"]
    ql.arch.regs.x3 = 0
    ql.arch.regs.x30 = _BASE["ret"]
    print(f"[kmt] decodeKeyBlob(blob={len(blob)}B = {blob.hex()})", flush=True)
    return True
