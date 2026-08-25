from .params import *
from pwn import *
from qiling import Qiling
import struct, os

# === keymint3 (dba51a17) STRUCTURE-AWARE harness v2 — Phase 3 (P3c) ===========
# Xiaomi MiTEE AOSP KeyMint 3.0. RE doc: RE/xiaomi_mitee/mitee_payment.md +
# RE/emulation/mitee_stateful_phase3.md (§keymint3).
#
# *** CORRECTION over the Wave-2 harness ***
#   Entry @0xC6CE0: gate paramTypes==0x65, then x22=params[0].buf, w20=params[0].size,
#   tail-call keymint_dispatcher @0xC6F38 with the GP cmd_id. Dispatcher jumptable
#   @0x1E830 indexes by GP cmd_id directly (cmd_id<=0x90) => **GP cmd_id IS the KeyMint
#   opcode**. Wave-2 used cmd_id=0x100 (>0x90) -> unimplemented default @0xCB5D8
#   (returns 0xFFFFFF9C) -> NO parser ever ran. v2 sets the GP cmd to the real opcode and
#   places a properly AOSP-serialized message in params[0].buf.
#
# Opcode map (GP cmd_id): 0x00 GENERATE_KEY, 0x04 BEGIN, 0x08 UPDATE, 0x0c FINISH,
#   0x14 IMPORT_KEY, 0x40 ATTEST_KEY, 0x44 UPGRADE_KEY, 0x64 IMPORT_WRAPPED_KEY,
#   0x74 RKP_KEY, 0x78 GEN_CSR, 0x90 GEN_CSR_V2.  (full table in the .md)
#
# Wire format (LE):
#   Blob    = u32 len | bytes                              (reader sub_91118)
#   AuthSet = u32 indirect_size | bytes | u32 count | u32 size | count*Entry   (sub_8fea0)
#   Entry   = u32 tag ; type=tag>>28 ; ENUM/UINT:+u32 ULONG/DATE:+u64 BOOL:+u8
#             BYTES/BIGNUM:+u32 length +u32 offset (offset+length<=indirect_size)
#
# Single-shot env knobs:
#   K_MODE   = which command body to build (default "genkey")
#   K_OUTSZ  = param1 output size (default 0x4000)
#   K_PT     = paramTypes (default 0x65 — the only accepted shape)
# AFL: the input bytes are spliced into the chosen MODE's mutable length/count/offset
#   fields (structure-aware) — see build_* below.
#
# MULTI-CMD (TAEMU_MULTI_CMD=N): each length-prefixed record's byte0 selects a MODE,
#   the rest is AFL entropy spliced into that body. Heap/session persist across records,
#   so a provisioning command (genkey/import) can set state a later command misuses.

K_OUTSZ = int(os.environ.get("K_OUTSZ", "0x4000"), 0)
PTYPES  = int(os.environ.get("K_PT", "0x65"), 0)

# ---- KeyMint tag constants (AOSP keymaster_tag_t; type in high nibble) -------
TAG_UINT   = 0x30000000
TAG_ULONG  = 0x50000000
TAG_ENUM   = 0x10000000
TAG_BOOL   = 0x70000000
TAG_BYTES  = 0x90000000
TAG_BIGNUM = 0x80000000
TAG_DATE   = 0x60000000
# concrete tags used in a benign key_description
KM_TAG_PURPOSE      = TAG_ENUM  | 1     # ENUM_REP purpose
KM_TAG_ALGORITHM    = TAG_ENUM  | 2
KM_TAG_KEY_SIZE     = TAG_UINT  | 3
KM_TAG_DIGEST       = TAG_ENUM  | 5
KM_TAG_EC_CURVE     = TAG_ENUM  | 10
KM_TAG_NO_AUTH_REQD = TAG_BOOL  | 503
KM_TAG_APP_ID       = TAG_BYTES | 601   # APPLICATION_ID (BYTES -> indirect data)
KM_ALG_EC = 3
KM_DIGEST_SHA256 = 4
KM_CURVE_P256 = 1


def u32(v): return struct.pack("<I", v & 0xFFFFFFFF)
def u64(v): return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def blob(data: bytes) -> bytes:
    return u32(len(data)) + data


def authset(entries: bytes, indirect: bytes = b"", count: int = None,
            elem_size: int = None, indirect_size: int = None) -> bytes:
    # entries already serialized; count/sizes overridable for fuzzing
    if count is None:
        # caller passes pre-counted; default 0
        count = 0
    if indirect_size is None:
        indirect_size = len(indirect)
    if elem_size is None:
        elem_size = len(entries)
    return u32(indirect_size) + indirect + u32(count) + u32(elem_size) + entries


def empty_authset() -> bytes:
    return u32(0) + u32(0) + u32(0)


# --- entry builders -----------------------------------------------------------
def e_uint(tag, v):   return u32(tag) + u32(v)
def e_ulong(tag, v):  return u32(tag) + u64(v)
def e_enum(tag, v):   return u32(tag) + u32(v)
def e_bool(tag):      return u32(tag) + b"\x01"
def e_bytes(tag, length, offset): return u32(tag) + u32(length) + u32(offset)


def good_key_description():
    # a plausible EC-P256 key_description (5 entries, no indirect data)
    ents = b"".join([
        e_enum(KM_TAG_ALGORITHM, KM_ALG_EC),
        e_uint(KM_TAG_KEY_SIZE, 256),
        e_enum(KM_TAG_EC_CURVE, KM_CURVE_P256),
        e_enum(KM_TAG_DIGEST, KM_DIGEST_SHA256),
        e_bool(KM_TAG_NO_AUTH_REQD),
    ])
    return authset(ents, indirect=b"", count=5, elem_size=len(ents))


# ============================================================================
# Structure-aware bodies. Each returns (body_bytes). `mut` = AFL entropy used to
# perturb the length/count/offset fields *inside* a valid skeleton.
# ============================================================================
def m32(mut, idx, default):
    # pull a u32 from the AFL stream at word index idx, else default
    o = idx * 4
    if mut is not None and len(mut) >= o + 4:
        return struct.unpack_from("<I", mut, o)[0]
    return default


def build_genkey(mut):
    # GENERATE_KEY: AuthSet key_description. Fuzz the AuthSet header fields +
    # an APPLICATION_ID BYTES entry's (length, offset) into a small indirect blob.
    ind = b"ABCD"  # 4-byte indirect data region
    ents = b"".join([
        e_enum(KM_TAG_ALGORITHM, KM_ALG_EC),
        e_uint(KM_TAG_KEY_SIZE, 256),
        e_bytes(KM_TAG_APP_ID, m32(mut, 0, 4), m32(mut, 1, 0)),  # length, offset (FUZZ)
    ])
    cnt   = m32(mut, 2, 3)
    esz   = m32(mut, 3, len(ents))
    isz   = m32(mut, 4, len(ind))
    return u32(isz) + ind + u32(cnt) + u32(esz) + ents


def build_import_key(mut):
    # IMPORT_KEY: AuthSet | u32 key_format | Blob key_material
    kd = good_key_description()
    keyfmt = m32(mut, 0, 0)
    mat_len = m32(mut, 1, 0x20)
    mat = bytes((mut[8:8 + (mat_len & 0xFFFF)] if mut else b"") .ljust(min(mat_len & 0xFFFF, 0x400), b"\x4b"))
    return kd + u32(keyfmt) + u32(mat_len) + mat


def build_import_wrapped(mut):
    # IMPORT_WRAPPED_KEY: Blob wrapped | Blob blob2 | Blob masking | AuthSet | u64 | u64
    # Fuzz the three blob lengths and the AuthSet header. All pre-crypto.
    wlen = m32(mut, 0, 0x40)
    blen = m32(mut, 1, 0x10)
    mlen = m32(mut, 2, 0x10)
    # supply real bytes only up to a sane cap; the length FIELD is what we mutate
    def body(n, fill):
        n2 = min(n & 0xFFFF, 0x800)
        return bytes([fill]) * n2
    wrapped = u32(wlen) + body(wlen, 0x57)
    b2      = u32(blen) + body(blen, 0x42)
    masking = u32(mlen) + body(mlen, 0x4d)
    # unwrapping_params AuthSet (fuzz count/size)
    ind = b"WXYZ"
    ents = e_bytes(KM_TAG_APP_ID, m32(mut, 3, 4), m32(mut, 4, 0))
    aset = u32(m32(mut, 5, len(ind))) + ind + u32(m32(mut, 6, 1)) + u32(m32(mut, 7, len(ents))) + ents
    return wrapped + b2 + masking + aset + u64(0) + u64(0)


def build_attest(mut):
    # ATTEST_KEY: Blob key_blob_to_attest | AuthSet attest_params
    klen = m32(mut, 0, 0x40)
    kb = u32(klen) + (bytes([0x4b]) * min(klen & 0xFFFF, 0x800))
    ind = b"chal"
    # attest params: ATTESTATION_CHALLENGE (BYTES) + APPLICATION_ID (BYTES)
    ents = b"".join([
        e_bytes(TAG_BYTES | 708, m32(mut, 1, 4), m32(mut, 2, 0)),  # challenge
        e_bytes(KM_TAG_APP_ID,   m32(mut, 3, 4), m32(mut, 4, 0)),
    ])
    aset = u32(m32(mut, 5, len(ind))) + ind + u32(m32(mut, 6, 2)) + u32(m32(mut, 7, len(ents))) + ents
    return kb + aset


def build_begin(mut):
    # BEGIN_OPERATION: u32 purpose | Blob key_blob | AuthSet in_params
    purpose = m32(mut, 0, 2)
    klen = m32(mut, 1, 0x20)
    kb = u32(klen) + (bytes([0x6b]) * min(klen & 0xFFFF, 0x400))
    aset = u32(m32(mut, 2, 0)) + u32(m32(mut, 3, 0)) + u32(m32(mut, 4, 0))
    return u32(purpose) + kb + aset


MODES = {
    "genkey":   (0x00, build_genkey),
    "import":   (0x14, build_import_key),
    "wrapped":  (0x64, build_import_wrapped),
    "attest":   (0x40, build_attest),
    "begin":    (0x04, build_begin),
}
MODE_LIST = list(MODES.keys())


def _emit(ql, mode, mut):
    cmd, builder = MODES[mode]
    body = builder(mut)
    insz = max(len(body), 0x10)
    buf = bytearray(insz)
    buf[:len(body)] = body
    print(f"[K2] mode={mode} cmd={cmd:#x} insz={insz:#x} bodylen={len(body)} pt={PTYPES:#x}")
    command_params = [
        MemRefParam(bytes(buf), insz),          # param0 MEMREF_INPUT  (serialized msg)
        MemRefParam(bytes(K_OUTSZ), K_OUTSZ),   # param1 MEMREF_OUTPUT (response)
        NoneParam(),
        NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)


def _emit_raw(ql, cmd, body):
    insz = max(len(body), 0x10)
    buf = bytearray(insz); buf[:len(body)] = body
    print(f"[K2-raw] cmd={cmd:#x} insz={insz:#x} bodylen={len(body)} pt={PTYPES:#x}")
    command_params = [
        MemRefParam(bytes(buf), insz),
        MemRefParam(bytes(K_OUTSZ), K_OUTSZ),
        NoneParam(), NoneParam(),
    ]
    setup_params_fuzz(ql, cmd, PTYPES, command_params)


def place_input_callback(ql: Qiling, input: bytes, _: int):
    # raw-hex probe: K_RAWHEX=<hex>, K_RAWCMD=<gp cmd> -> inject exact bytes
    rawhex = os.environ.get("K_RAWHEX", "")
    if rawhex:
        cmd = int(os.environ.get("K_RAWCMD", "0x0"), 0)
        _emit_raw(ql, cmd, bytes.fromhex(rawhex.replace(" ", "")))
        return True
    MULTI = int(os.environ.get("TAEMU_MULTI_CMD", "0"))
    if MULTI > 0:
        # multi-cmd: byte0 selects MODE, rest is the mutation stream
        if len(input) >= 1:
            mode = MODE_LIST[input[0] % len(MODE_LIST)]
            mut = input[1:]
        else:
            mode = "genkey"; mut = b""
        _emit(ql, mode, mut)
        return True
    # single-shot: MODE pinned by env (K_MODE), AFL stream perturbs its fields
    mode = os.environ.get("K_MODE", "genkey")
    if mode not in MODES:
        mode = "genkey"
    _emit(ql, mode, input)
    return True
