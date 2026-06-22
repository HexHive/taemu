#from params import *
from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === widevine_real / OEMCrypto v19.x (e97c270e) STATEFUL harness (Phase-3) =====
#
# Solves the Wave-2 blocker. Wave-2 used the disk-.elf top-struct tag (7); the STAGED
# .ta wants tag **6**. The GEN_tee_serializer wire format (re-derived from the .ta):
#   each value = [u8 tag][value]; readers (mov w1,#tag; bl CheckTag@0x74e48):
#     tag1=bool(1B) tag3=u64(8B,LE) tag6=u32(4B,LE) tag7=u64(8B,LE)/fixed-bytes
#     tag8=byte-array(len-prefixed) tag9=substring tagA=struct-CLOSE
#   verbatim contiguous read from offset 0, cursor bounded vs payload_len.
#
# ENTRY GATE (.ta @0x50078): GP cmd==0, paramTypes==0x177, param1.size<=0x8000,
#   param2.value.a(payload_len)<=param1.size, memcpy(staging, param1.buf, payload_len).
#   FRAME GOES IN param1; param0 = INOUT scratch/out; param2.value.a = len(frame).
#
# MESSAGE = [06][u32 cmd LE] <per-cmd fields> [0A]. Each unpacker re-reads [06 cmd]
#   (cmp ==N) then its fields then [0A].
#
# MULTI-COMMAND (TAEMU_MULTI_CMD=N): emulator frames AFL input as N records
#   [u16 LE len][bytes]; each record is one InvokeCommand (heap/session/global state
#   persists). Here each record's byte0 selects a step in the DRM state-machine PLAN
#   and the rest is mutated into that step's structure-aware frame.
#
# Modes:
#   E97C_RAWHEX=<hex>  : single InvokeCommand, param1 = exactly these bytes (probe).
#   E97C_PLAN=<csv>    : fixed sequence of step names for MULTI_CMD replay/seed (e.g.
#                        "init,open,loadlic,cenc"). byte0 of each record indexes PLAN.
#   E97C_CMD=<n>       : pin a raw cmd id; body = E97C_BODYHEX or input.
#   default (no env)   : single-cmd; AFL byte0 -> a cmd from IMPL_CMDS, body=input[1:].

TAG6, TAG7, TAG1, TAG3, TAGA = 6, 7, 1, 3, 0xA
GP_CMD = 0
PTYPES = 0x177
TA_BASE = 0x555555554000

# --- LoadLicense MAC-stub (legitimate precondition model) ---------------------
# LoadLicense (cmd 99) HMAC-SHA256-verifies the license MAC via OPKI_VerifyMessage
# @0x5c8d8 BEFORE the content-key parser @0x52704. The MAC key is the PER-SESSION
# MAC key (slot type 0xa09c9790) derived during the license handshake — a
# malicious/compromised license SERVER (or session-key MITM) legitimately KNOWS it,
# so producing a valid MAC is within that adversary's power. To reach the parser in
# the emulator (which has no negotiated session key) we STUB the verify to succeed
# (patch 0x5c8d8 -> `mov w0,#0; ret`). This models "the malicious server has a valid
# MAC"; it does NOT fabricate a device-secret bypass. DOCUMENTED stub.
MAC_STUB_VA = 0x5c8d8
_MAC_STUB_BYTES = bytes.fromhex("00008052c0035fd6")  # mov w0,#0 ; ret
_stub_applied = {"v": False}

def _apply_mac_stub(ql):
    if _stub_applied["v"] or os.environ.get("E97C_NO_MAC_STUB"):
        return
    ql.mem.write(TA_BASE + MAC_STUB_VA, _MAC_STUB_BYTES)
    _stub_applied["v"] = True
    print(f"[e97c-sf] applied LoadLicense MAC stub @0x{MAC_STUB_VA:x} (mov w0,#0;ret)")
P0SZ = int(os.environ.get("E97C_P0SZ", str(0x4000)), 0)   # param0 INOUT scratch/out
P1SZ_MAX = 0x8000

# ---- typed-value encoders ----------------------------------------------------
def t_u32(v):  return bytes([TAG6]) + struct.pack("<I", v & 0xFFFFFFFF)
def t_u64(v):  return bytes([TAG7]) + struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
def t3_u64(v): return bytes([TAG3]) + struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
def t_bool(b): return bytes([TAG1]) + bytes([1 if b else 0])
def t_close(): return bytes([TAGA])
def hdr(cmd):  return t_u32(cmd)   # [06][u32 cmd]

# ---- structure-aware frame builders for each state-machine step --------------
# (field layouts re-derived from each OPK_Unpack_<Cmd>_Request in the .ta)

def f_initialize(b=b""):
    # cmd 1: [06 1][07 u64][0A]
    return hdr(1) + t_u64(0) + t_close()

def f_opensession(session_id=0x1111, b=b""):
    # cmd 9: [06 9][07 u64 session_id][01 present=0][0A]
    return hdr(9) + t_u64(session_id) + t_bool(False) + t_close()

def f_apiversion(b=b""):
    return hdr(22) + t_u64(0) + t_close()

# DecryptCENC (cmd 134) unpacker 0x6b3e8 — FULL field layout (re-derived empirically;
# reaches the impl _oecc134 @0x54330):
#   [06 134][07 u64 reserved][03 u64 buffer_length][03 u64 subsample_count(=N)]
#   [08 buffer-descriptor][01 bool flag]
#   N x <subsample struct (reader 0x739b8, 0x50-byte parsed)>
#   [pattern (reader 0x73e80): 01 has_pattern; if 0 -> 03 u64 enc, 03 u64 skip][0A]
# Buffer descriptor (reader 0x757f8): [08][01 absent_bool][03 u64 size]; absent_bool!=0
#   -> NULL (no size); ==0 -> read size, and size MUST == buffer_length (consistency
#   check @0x75934) and buffer_offset+size <= payload_len. So desc_size == buffer_length.
def _tag8_bufdesc(size=0, absent=False, data=None):
    # reader 0x757f8 advances the cursor by `size` after reading the size word, i.e.
    # `size` bytes of inline buffer data MUST follow on the wire.
    if absent:
        return bytes([8]) + t_bool(True)
    payload = (data or b"")[:size].ljust(size, b"\x00")
    return bytes([8]) + t_bool(False) + t3_u64(size) + payload

# One subsample struct on the wire (reader 0x739b8). It is itself a nested typed struct:
#   [03 u64][03 u64][<tag-8 array via 0x75a00>][<0x737d0 sub>][16-byte field 0x75750]
#   [<tag-8 array via 0x74068/0x753e8 + nested 0x20-count>] ...
# Building a fully-valid subsample requires the nested array fields; for COUNT-overflow
# fuzzing we drive subsample_count huge with count==0 actual structs is impossible (the
# loop reads `count` structs). So the practical fuzz of the impl's subsample math uses a
# small count with one hand-built struct (sub_struct below), or count==0 to reach the
# impl with an empty table (proves reachability + init/session gates).
def _frag(a=0, b=0, c=0, d=0):
    # ONE subsample FRAGMENT (loop @0x73b64, stride 0x20):
    #   [03 u64 A][03 u64 B][04 byte C][03 u64 D]
    # A,B are summed with overflow checks in the impl subsample math (clear/cipher byte
    # counts) -> the OOB-arithmetic fuzz target.
    return t3_u64(a) + t3_u64(b) + bytes([4]) + bytes([c & 0xFF]) + t3_u64(d)

def _subsample_struct(field_b=0, frags=None, iv=None, keyid=None):
    # ONE subsample struct (reader 0x739b8 = OPK_Unpack_OEMCrypto_SampleDescription):
    #   [03 u64 FIELD_A]   <- this is the fragment COUNT (read into [x28+0x48], used as
    #                          the array length @0x73a68 + parity-gated EVEN @0x73a90)
    #   [03 u64 field_b]   <- a separate field (read into [x28+8])
    #   [09 key-id (absent)] [06 u32 DestBuf sel=2][01 flag] [08 IV (absent)]
    #   [01 bool array-NULL] (0 => parse FIELD_A fragments; 1 => skip)
    #   if array-NULL==0: FIELD_A x <fragment (0x20)>
    frags = frags or []
    nfrag = len(frags)
    if nfrag % 2 == 1:                     # count (field_a) must be EVEN
        frags = frags + [_frag()]
        nfrag += 1
    fr  = t3_u64(nfrag)                    # FIELD_A = fragment count (even)
    fr += t3_u64(field_b)                  # field_b (separate)
    fr += bytes([9]) + t_bool(True)        # key-id absent
    fr += t_u32(2) + t_bool(False)         # DestBuf sel=2, flag=0
    if iv is None:
        fr += bytes([8]) + t_bool(True)    # IV absent
    else:
        fr += bytes([8]) + t_bool(False) + t3_u64(0x10) + iv[:0x10].ljust(0x10, b"\x00")
    if nfrag == 0:
        fr += t_bool(True)                 # array-NULL (no fragments)
    else:
        fr += t_bool(False)                # parse the fragment array
        fr += b"".join(frags)
    return fr

def f_decryptcenc(session_id=0x1111, buffer_length=0, subsample_count=0,
                  flag=0, has_pattern=1, enc_blocks=1, skip_blocks=0,
                  subsamples=b"", buffer_data=None, b=b""):
    fr  = hdr(134)
    fr += t_u64(session_id)               # [07] reserved/handle
    fr += t3_u64(buffer_length)           # [03] buffer_length
    fr += t3_u64(subsample_count)         # [03] subsample_count  <<< COUNT (fuzz)
    fr += _tag8_bufdesc(buffer_length, data=buffer_data)  # [08] descriptor (size==buffer_length) + inline buf
    fr += t_bool(flag)                    # [01] flag
    fr += subsamples                      # N x subsample struct (caller supplies bytes)
    fr += t_bool(has_pattern)             # pattern: has_pattern (true => no enc/skip)
    if not has_pattern:
        fr += t3_u64(enc_blocks)
        fr += t3_u64(skip_blocks)
    fr += t_close()
    return fr

# LoadLicense (cmd 99 / 0x63) unpacker 0x6a0a8, impl 0x52330:
#   parses [06 99][07 u64 session][... license proto bytes ...] then MAC-verifies
#   (0x5c8d8) BEFORE the content-key extraction loop @0x52704. Field layout is a
#   nested SignedMessage struct; built dynamically by the fuzzer body when targeted.
#   (Exact sub-fields are appended by the per-step mutation below.)
def _tag8_array(data, absent=False):
    # tag-8 byte-array: [08][01 absent_bool][03 u64 len][len bytes]
    if absent:
        return bytes([8]) + t_bool(True)
    return bytes([8]) + t_bool(False) + t3_u64(len(data)) + data

# LoadLicense (cmd 99) request layout (unpacker 0x6a0a8; impl 0x52330):
#   [06 99][07 u64 session][03 u64][03 u64][06 u32]
#   [08 SignedMessage license blob]   <-- protobuf-decoded by 0x61d40 then MAC-verified
#   [03 u64][08 secondary blob][0A]
# The FIRST tag-8 array is the license blob (the fuzz target; its fields are parsed by
# the hardened key-array loop AFTER the MAC stub lets it through).
def f_loadlicense(session_id=0x1111, license_blob=b"", f3=0, f4=0, f5=0, secondary=b"", body=None):
    blob = body if body is not None else license_blob
    fr  = hdr(99)
    fr += t_u64(session_id)
    fr += t3_u64(f3)
    fr += t3_u64(f4)
    fr += t_u32(f5)
    fr += _tag8_array(blob)            # SignedMessage license blob (FUZZ)
    fr += t3_u64(0)
    fr += _tag8_array(secondary)       # secondary blob
    fr += t_close()
    return fr

# LoadEntitledContentKeys (cmd 121) unpacker 0x6aa48:
#   [06 121][07 u64 session][03 u64 a][03 u64 b][06 u32 KEY_COUNT]
#   [08 <key-block>][01 present][ count x 88B substring-range array ][0A]
def f_loadentitled(session_id=0x1111, fa=0, fb=0, key_count=1, block_size=0x20,
                   present=1, key_array=b"", b=b""):
    fr  = hdr(121)
    fr += t_u64(session_id)
    fr += t3_u64(fa)
    fr += t3_u64(fb)
    fr += t_u32(key_count)                # <<< COUNT (x88 array)
    fr += bytes([8]) + struct.pack("<I", block_size) + b"\x00" * block_size  # tag8 block
    fr += t_bool(present)
    fr += key_array
    fr += t_close()
    return fr

STEPS = {
    "init":     f_initialize,
    "open":     f_opensession,
    "api":      f_apiversion,
    "cenc":     f_decryptcenc,
    "loadlic":  f_loadlicense,
    "loadent":  f_loadentitled,
}

# param1 is MEMREF_INOUT: the TA reads the request from it AND writes the response
# BACK into it. So param1's *declared size* must be >= the RESPONSE size (which can
# exceed the request frame). We declare it P1DECL and only payload_len bytes carry the
# request; the gate requires payload_len <= param1.size <= 0x8000.
P1DECL = int(os.environ.get("E97C_P1DECL", str(0x2000)), 0)

def _place_frame(ql, frame):
    _apply_mac_stub(ql)   # idempotent; models malicious-server-has-valid-MAC for LoadLicense
    if len(frame) > P1SZ_MAX:
        frame = frame[:P1SZ_MAX]
    payload_len = len(frame)
    p1size = max(P1DECL, payload_len)
    if p1size > P1SZ_MAX:
        p1size = P1SZ_MAX
    p1buf = frame + b"\x00" * (p1size - len(frame))   # request at start, room for response
    command_params = [
        MemRefParam(bytes(P0SZ), P0SZ),       # param0 INOUT scratch/out (redzoned)
        MemRefParam(p1buf, p1size),           # param1 INOUT: request in[:payload_len], response out
        ValueParam(payload_len, 0),           # param2.value.a = payload_len (request length)
        NoneParam(),
    ]
    setup_params_fuzz(ql, GP_CMD, PTYPES, command_params)
    return True

IMPL_CMDS = [1,2,3,4,5,7,8,9,10,14,22,29,32,36,37,38,39,41,44,45,46,49,52,54,61,62,
    63,64,65,66,67,68,71,78,84,85,86,89,93,94,96,97,98,99,101,103,104,107,108,109,
    110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,
    129,130,131,132,133,134,135,136,137,138,139,140,141,142,143]

def place_input_callback(ql: Qiling, input: bytes, idx: int):
    raw = os.environ.get("E97C_RAWHEX")
    if raw is not None:
        return _place_frame(ql, bytes.fromhex(raw))

    plan = os.environ.get("E97C_PLAN")
    if plan is not None:
        names = plan.split(",")
        # In MULTI_CMD, idx is the op index; map it to the plan step. byte0 can carry
        # a mutation selector for the fuzz-critical field of that step.
        step = names[idx % len(names)] if idx >= 0 else names[0]
        sel = input[0] if len(input) else 0
        body = input[1:]
        frame = _build_step(step, sel, body)
        print(f"[e97c-sf] op#{idx} step={step} sel={sel} -> {len(frame)} B")
        return _place_frame(ql, frame)

    pin = os.environ.get("E97C_CMD")
    if pin is not None:
        cmd = int(pin, 0)
        bh = os.environ.get("E97C_BODYHEX")
        body = bytes.fromhex(bh) if bh is not None else bytes(input)
        return _place_frame(ql, hdr(cmd) + body + t_close())

    if len(input) < 1:
        return False
    cmd = IMPL_CMDS[input[0] % len(IMPL_CMDS)]
    return _place_frame(ql, hdr(cmd) + bytes(input[1:]) + t_close())

def _build_step(step, sel, body):
    if step == "cenc":
        # structure-aware CENC fuzz reaching the impl subsample MATH (0x54424 loop):
        #   1 subsample with 2 fragments; the fragment A/B u64s (clear/cipher byte
        #   counts) are the OOB-arithmetic targets, summed with overflow checks then
        #   compared vs buffer_length. body carries fragA, fragB (the attacker counts).
        blen = 0x10 + (((sel >> 3) & 0x1f) * 0x10)      # inline buffer length (>=4)
        a = int.from_bytes((body[0:8] + b"\x00"*8)[:8], "little") if body else 0
        bb = int.from_bytes((body[8:16] + b"\x00"*8)[:8], "little") if len(body) > 8 else 0
        d = int.from_bytes((body[16:24] + b"\x00"*8)[:8], "little") if len(body) > 16 else 0
        frags = [_frag(a=a, b=bb, c=1, d=d), _frag(a=0, b=0, c=0, d=0)]
        subs = _subsample_struct(field_b=0x10, frags=frags)
        return f_decryptcenc(buffer_length=blen, subsample_count=1,
                             subsamples=subs, buffer_data=b"\xAA"*blen, has_pattern=1)
    if step == "cenc_huge":
        # drive subsample_count huge to probe the count*0x50 overflow + impl array walk;
        # NOTE: with a huge count the unpacker tries to read `count` structs and will
        # underflow the frame, but the count*0x50 multiply-overflow gate fires first.
        huge = int.from_bytes((body[0:8] + b"\x00"*8)[:8], "little") if body else 0xFFFFFFFFFFFFFFFF
        return f_decryptcenc(buffer_length=0, subsample_count=huge,
                             subsamples=b"", has_pattern=1)
    if step == "loadlic":
        # the body bytes become the SignedMessage license blob (protobuf -> key-array).
        return f_loadlicense(license_blob=body)
    if step == "loadent":
        return f_loadentitled(b=body)
    fn = STEPS.get(step, f_apiversion)
    return fn(b=body)
