# scrypto_api.py — Samsung libscrypto (BoringSSL fork) shim over PyCryptodome.
#
# TEEGRIS userspace TAs link libscrypto.so, a BoringSSL fork, and reach it
# through the versioned symbols `EVP_*@TEEGRIS_5`, `SHA256_*@TEEGRIS_5`, etc.
# The loader strips the `@TEEGRIS_5` version tag, so the resolver looks up the
# bare names defined here (wired into emulator_no_loader.get_api_impl).
#
# Design goal (see RE/samsung_teegris/fbckmr.md Finding #1): the EVP cipher
# family must be **length-faithful** — EVP_DecryptUpdate writes `inlen` bytes
# of plaintext to the caller's destination pointer *before* the GCM tag is
# verified by EVP_DecryptFinal_ex. When the destination is an undersized stack
# buffer (fk_aes_gcm_decrypt @0x11168 -> v94[520]) that write smashes the stack
# canary, surfacing as __stack_chk_fail (-> common.crash). Cryptographic
# correctness is irrelevant to the overflow; the output *length* is what
# manifests it, so we always emit len(input) bytes regardless of key validity.
#
# The asymmetric / ASN.1 family (PKEY/EC/ASN1/d2i/i2d) is stubbed to plausible
# non-crashing handles/lengths so non-GCM code paths proceed far enough to
# reach (or rule out) their own sinks; these are NOT real RSA/EC operations and
# are logged as stubs.

from qiling import Qiling
from qiling.os.const import STRING, INT, UINT, BYTE, POINTER
from .common import crash, crash_notimpl, HEAP_MEM
import unicorn

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
    from Crypto.Hash import HMAC as _PHMAC
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
    _HAVE_PYCRYPTO = True
except Exception:                                   # pragma: no cover
    _HAVE_PYCRYPTO = False

# ---- cipher sentinels returned by EVP_aes_*; the TA only passes them back to
# ---- EVP_{De,En}cryptInit_ex as opaque `const EVP_CIPHER *`. ----------------
CIPHER_AES_128_GCM = 0x5C000080
CIPHER_AES_256_GCM = 0x5C000100
_CIPHER_KEYLEN = {CIPHER_AES_128_GCM: 16, CIPHER_AES_256_GCM: 32}

# ---- md sentinels returned by EVP_sha*; passed back as `const EVP_MD *`. ----
MD_SHA1   = 0x5D000001
MD_SHA256 = 0x5D000256
MD_SHA384 = 0x5D000384

# BoringSSL EVP_CTRL_* (AEAD aliases collapse onto the GCM values).
EVP_CTRL_AEAD_SET_IVLEN = 0x9
EVP_CTRL_AEAD_GET_TAG   = 0x10
EVP_CTRL_AEAD_SET_TAG   = 0x11

# handle -> state dicts (keyed by the synthetic pointer we hand back)
_CIPHER_CTXS = {}     # cipher ctx
_MD_CTXS = {}         # SHA*_Init style ctx (keyed by caller's ctx pointer)
_PKEY_OBJS = {}       # opaque asymmetric handles -> kind string


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _ret(ql, val):
    ql.os.fcall.cc.setReturnValue(val)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def _void(ql):
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def _handle(ql, tag="scrypto_obj"):
    # A real, uniquely-mapped page so the returned pointer is valid if the TA
    # ever (defensively) dereferences it. We only ever key state by its value.
    return ql.mem.map_anywhere(0x1000, minaddr=HEAP_MEM, perms=3, info=tag)


def _wr_u32(ql, addr, val):
    if addr:
        ql.mem.write(addr, int(val).to_bytes(4, "little"))


# ---------------------------------------------------------------------------
# OPENSSL_STACK (sk_* / OPENSSL_sk_*) — a growable pointer-array container, not
# a cryptographic primitive. KeyMaster's TA_OpenSessionEntryPoint builds a cert
# stack via sk_new_null during "Tl initialization"; without it OpenSession dies
# before the TA is ever drivable. Model it faithfully with a Python list keyed
# by the handle we hand back; it stores opaque guest pointers (e.g. X509*).
# ---------------------------------------------------------------------------
_STACKS = {}   # handle -> python list of guest pointers

def _sk_new(ql, hook_data):
    h = _handle(ql, "OPENSSL_STACK")
    _STACKS[h] = []
    _ret(ql, h)

def sk_new_null(ql, hook_data):   _sk_new(ql, hook_data)
def sk_new(ql, hook_data):        _sk_new(ql, hook_data)
def OPENSSL_sk_new_null(ql, hook_data): _sk_new(ql, hook_data)
def OPENSSL_sk_new(ql, hook_data):      _sk_new(ql, hook_data)

def _sk_push(ql, hook_data):
    p = ql.os.resolve_fcall_params({"sk": POINTER, "ptr": POINTER})
    lst = _STACKS.get(p["sk"])
    if lst is None:
        _ret(ql, 0); return
    lst.append(p["ptr"])
    _ret(ql, len(lst))     # OpenSSL returns the new element count

def sk_push(ql, hook_data):          _sk_push(ql, hook_data)
def OPENSSL_sk_push(ql, hook_data):  _sk_push(ql, hook_data)

def _sk_num(ql, hook_data):
    p = ql.os.resolve_fcall_params({"sk": POINTER})
    lst = _STACKS.get(p["sk"])
    _ret(ql, len(lst) if lst is not None else 0xFFFFFFFF)  # -1 for NULL stack

def sk_num(ql, hook_data):          _sk_num(ql, hook_data)
def OPENSSL_sk_num(ql, hook_data):  _sk_num(ql, hook_data)

def _sk_value(ql, hook_data):
    p = ql.os.resolve_fcall_params({"sk": POINTER, "i": INT})
    lst = _STACKS.get(p["sk"])
    if lst is None or not (0 <= p["i"] < len(lst)):
        _ret(ql, 0); return
    _ret(ql, lst[p["i"]])

def sk_value(ql, hook_data):          _sk_value(ql, hook_data)
def OPENSSL_sk_value(ql, hook_data):  _sk_value(ql, hook_data)

def _sk_pop(ql, hook_data):
    p = ql.os.resolve_fcall_params({"sk": POINTER})
    lst = _STACKS.get(p["sk"])
    _ret(ql, lst.pop() if lst else 0)

def sk_pop(ql, hook_data):          _sk_pop(ql, hook_data)
def OPENSSL_sk_pop(ql, hook_data):  _sk_pop(ql, hook_data)

def _sk_free(ql, hook_data):
    p = ql.os.resolve_fcall_params({"sk": POINTER})
    _STACKS.pop(p["sk"], None)
    _void(ql)

def sk_free(ql, hook_data):              _sk_free(ql, hook_data)
def sk_pop_free(ql, hook_data):          _sk_free(ql, hook_data)
def OPENSSL_sk_free(ql, hook_data):      _sk_free(ql, hook_data)
def OPENSSL_sk_pop_free(ql, hook_data):  _sk_free(ql, hook_data)

def _sk_zero(ql, hook_data):
    p = ql.os.resolve_fcall_params({"sk": POINTER})
    lst = _STACKS.get(p["sk"])
    if lst is not None:
        lst.clear()
    _void(ql)

def sk_zero(ql, hook_data):          _sk_zero(ql, hook_data)
def OPENSSL_sk_zero(ql, hook_data):  _sk_zero(ql, hook_data)


# ---------------------------------------------------------------------------
# BoringSSL RNG configuration — no-ops in the emulator (RNG never forks).
# ---------------------------------------------------------------------------
def RAND_enable_fork_unsafe_buffering(ql, hook_data):
    _void(ql)


# ---------------------------------------------------------------------------
# EVP cipher selectors
# ---------------------------------------------------------------------------
def EVP_aes_256_gcm(ql: Qiling, hook_data):
    _ret(ql, CIPHER_AES_256_GCM)


def EVP_aes_128_gcm(ql: Qiling, hook_data):
    _ret(ql, CIPHER_AES_128_GCM)


def EVP_sha1(ql: Qiling, hook_data):
    _ret(ql, MD_SHA1)


def EVP_sha256(ql: Qiling, hook_data):
    _ret(ql, MD_SHA256)


def EVP_sha384(ql: Qiling, hook_data):
    _ret(ql, MD_SHA384)


# ---------------------------------------------------------------------------
# EVP_CIPHER_CTX lifecycle
# ---------------------------------------------------------------------------
def EVP_CIPHER_CTX_new(ql: Qiling, hook_data):
    ctx = _handle(ql, "EVP_CIPHER_CTX")
    _CIPHER_CTXS[ctx] = {"cipher": None, "key": None, "iv": None,
                         "ivlen": 12, "tag": None, "obj": None, "mode": None}
    ql.log.info(f"EVP_CIPHER_CTX_new -> {hex(ctx)}")
    _ret(ql, ctx)


def EVP_CIPHER_CTX_free(ql: Qiling, hook_data):
    ctx = ql.os.resolve_fcall_params({"ctx": POINTER})["ctx"]
    _CIPHER_CTXS.pop(ctx, None)
    _void(ql)


def EVP_CIPHER_CTX_cleanup(ql: Qiling, hook_data):
    ctx = ql.os.resolve_fcall_params({"ctx": POINTER})["ctx"]
    st = _CIPHER_CTXS.get(ctx)
    if st is not None:
        st.update({"obj": None, "key": None, "iv": None, "tag": None})
    _ret(ql, 1)


def EVP_CIPHER_CTX_init(ql: Qiling, hook_data):
    # In BoringSSL this zero-inits a caller-provided (often stack) ctx. We just
    # register the pointer as a fresh state slot keyed by its address. void.
    ctx = ql.os.resolve_fcall_params({"ctx": POINTER})["ctx"]
    _CIPHER_CTXS[ctx] = {"cipher": None, "key": None, "iv": None,
                         "ivlen": 12, "tag": None, "obj": None, "mode": None}
    _void(ql)


def EVP_CIPHER_CTX_set_padding(ql: Qiling, hook_data):
    _ret(ql, 1)


def EVP_CIPHER_CTX_ctrl(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
        {"ctx": POINTER, "type": INT, "arg": INT, "ptr": POINTER})
    ctx, typ, arg, ptr = p["ctx"], p["type"], p["arg"], p["ptr"]
    st = _CIPHER_CTXS.get(ctx)
    if st is None:
        ql.log.warning(f"EVP_CIPHER_CTX_ctrl on unknown ctx {hex(ctx)}")
        _ret(ql, 1)
        return
    try:
        if typ == EVP_CTRL_AEAD_SET_IVLEN:
            st["ivlen"] = arg
            ql.log.info(f"EVP_CIPHER_CTX_ctrl SET_IVLEN={arg}")
        elif typ == EVP_CTRL_AEAD_SET_TAG:
            st["tag"] = bytes(ql.mem.read(ptr, arg)) if ptr else None
            ql.log.info(f"EVP_CIPHER_CTX_ctrl SET_TAG len={arg}")
        elif typ == EVP_CTRL_AEAD_GET_TAG:
            obj = st.get("obj")
            tag = b"\x00" * arg
            if obj is not None:
                try:
                    tag = obj.digest()[:arg]
                except Exception:
                    pass
            if ptr:
                ql.mem.write(ptr, tag)
            ql.log.info(f"EVP_CIPHER_CTX_ctrl GET_TAG len={arg}")
        else:
            ql.log.info(f"EVP_CIPHER_CTX_ctrl type={hex(typ)} arg={arg} (noop)")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    _ret(ql, 1)


# ---------------------------------------------------------------------------
# EVP cipher init / update / final  (Decrypt + Encrypt)
# ---------------------------------------------------------------------------
def _init_common(ql, hook_data, mode):
    p = ql.os.resolve_fcall_params(
        {"ctx": POINTER, "cipher": POINTER, "impl": POINTER,
         "key": POINTER, "iv": POINTER})
    ctx = p["ctx"]
    st = _CIPHER_CTXS.setdefault(
        ctx, {"cipher": None, "key": None, "iv": None, "ivlen": 12,
              "tag": None, "obj": None, "mode": None})
    st["mode"] = mode
    try:
        if p["cipher"]:
            st["cipher"] = p["cipher"]
        if p["key"]:
            klen = _CIPHER_KEYLEN.get(st.get("cipher"), 32)
            st["key"] = bytes(ql.mem.read(p["key"], klen))
        if p["iv"]:
            st["iv"] = bytes(ql.mem.read(p["iv"], st.get("ivlen", 12)))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    # (re)build the underlying GCM object once we have key + iv
    st["obj"] = None
    if _HAVE_PYCRYPTO and st.get("key") and st.get("iv"):
        try:
            st["obj"] = AES.new(st["key"], AES.MODE_GCM, nonce=st["iv"])
        except Exception as e:
            ql.log.info(f"scrypto GCM obj build failed ({e}); length-faithful echo")
            st["obj"] = None
    ql.log.info(f"EVP_{mode}Init_ex ctx={hex(ctx)} "
                f"cipher={hex(st.get('cipher') or 0)} keyed={st.get('key') is not None}")
    _ret(ql, 1)


def EVP_DecryptInit_ex(ql: Qiling, hook_data):
    _init_common(ql, hook_data, "Decrypt")


def EVP_EncryptInit_ex(ql: Qiling, hook_data):
    _init_common(ql, hook_data, "Encrypt")


def _update_common(ql, hook_data):
    # (ctx, out, *outl, in, inl) — produces exactly inl bytes at `out`.
    p = ql.os.resolve_fcall_params(
        {"ctx": POINTER, "out": POINTER, "outl": POINTER,
         "inp": POINTER, "inl": INT})
    ctx, out, outl, inp, inl = p["ctx"], p["out"], p["outl"], p["inp"], p["inl"]
    st = _CIPHER_CTXS.get(ctx)
    try:
        data_in = bytes(ql.mem.read(inp, inl)) if (inp and inl) else b""
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    # length-faithful transform: AES-GCM/CTR keep |out| == |in|.
    out_bytes = data_in
    obj = st.get("obj") if st else None
    if obj is not None:
        try:
            if st.get("mode") == "Encrypt":
                out_bytes = obj.encrypt(data_in)
            else:
                out_bytes = obj.decrypt(data_in)
        except Exception:
            out_bytes = data_in            # stay length-faithful on any error
    ql.log.info(f"EVP_{(st or {}).get('mode','?')}Update ctx={hex(ctx)} "
                f"in={hex(inp)} inl={hex(inl)} out={hex(out)} "
                f"(writing {len(out_bytes)} bytes)")
    try:
        if out and out_bytes:
            ql.mem.write(out, out_bytes)   # <-- the (potentially OOB) write
            hook_data.emu.writeback_shm(out)
    except unicorn.unicorn_py3.unicorn.UcError:
        # write crossed an unmapped page: that IS the overflow boundary.
        crash(ql, hook_data.func_name)
        return
    _wr_u32(ql, outl, len(out_bytes))
    _ret(ql, 1)


def EVP_DecryptUpdate(ql: Qiling, hook_data):
    _update_common(ql, hook_data)


def EVP_EncryptUpdate(ql: Qiling, hook_data):
    _update_common(ql, hook_data)


def EVP_DecryptFinal_ex(ql: Qiling, hook_data):
    # Verify the GCM tag. Realistically fails (we lack the genuine key/tag),
    # which is the documented trigger for the *second* OOB memset in
    # fk_aes_gcm_decrypt. Either way the canary smash already happened in Update.
    p = ql.os.resolve_fcall_params({"ctx": POINTER, "out": POINTER, "outl": POINTER})
    ctx, outl = p["ctx"], p["outl"]
    st = _CIPHER_CTXS.get(ctx)
    ok = 0
    obj = st.get("obj") if st else None
    tag = st.get("tag") if st else None
    if obj is not None and tag is not None:
        try:
            obj.verify(tag)
            ok = 1
        except Exception:
            ok = 0
    _wr_u32(ql, outl, 0)
    ql.log.info(f"EVP_DecryptFinal_ex ctx={hex(ctx)} -> {ok} (tag {'ok' if ok else 'MISMATCH'})")
    _ret(ql, ok)


def EVP_EncryptFinal_ex(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"ctx": POINTER, "out": POINTER, "outl": POINTER})
    _wr_u32(ql, p["outl"], 0)
    _ret(ql, 1)


# ---------------------------------------------------------------------------
# one-shot digests (SHA*_Init/Update/Final keyed by caller ctx pointer)
# ---------------------------------------------------------------------------
def _sha_new(kind):
    if not _HAVE_PYCRYPTO:
        return None
    return {"sha1": SHA1, "sha256": SHA256, "sha384": SHA384}[kind].new()


def _sha_init(ql, kind):
    ctx = ql.os.resolve_fcall_params({"ctx": POINTER})["ctx"]
    _MD_CTXS[ctx] = _sha_new(kind)
    _ret(ql, 1)


def _sha_update(ql, hook_data):
    p = ql.os.resolve_fcall_params({"ctx": POINTER, "data": POINTER, "len": INT})
    h = _MD_CTXS.get(p["ctx"])
    try:
        if h is not None and p["data"] and p["len"]:
            h.update(bytes(ql.mem.read(p["data"], p["len"])))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    _ret(ql, 1)


def _sha_final(ql, digest_len):
    p = ql.os.resolve_fcall_params({"md": POINTER, "ctx": POINTER})
    h = _MD_CTXS.pop(p["ctx"], None)
    dig = h.digest() if h is not None else (b"\x00" * digest_len)
    try:
        if p["md"]:
            ql.mem.write(p["md"], dig[:digest_len])
    except unicorn.unicorn_py3.unicorn.UcError:
        pass
    _ret(ql, 1)


def SHA256_Init(ql, hook_data):   _sha_init(ql, "sha256")
def SHA256_Update(ql, hook_data): _sha_update(ql, hook_data)
def SHA256_Final(ql, hook_data):  _sha_final(ql, 32)
def SHA384_Init(ql, hook_data):   _sha_init(ql, "sha384")
def SHA384_Update(ql, hook_data): _sha_update(ql, hook_data)
def SHA384_Final(ql, hook_data):  _sha_final(ql, 48)


def HMAC(ql: Qiling, hook_data):
    # HMAC(evp_md, key, key_len, data, data_len, out, *out_len) -> out
    p = ql.os.resolve_fcall_params(
        {"evp_md": POINTER, "key": POINTER, "key_len": INT,
         "data": POINTER, "data_len": INT, "out": POINTER, "out_len": POINTER})
    digmod = {MD_SHA1: SHA1, MD_SHA256: SHA256, MD_SHA384: SHA384}.get(
        p["evp_md"], SHA256) if _HAVE_PYCRYPTO else None
    dig = b"\x00" * 32
    try:
        if _HAVE_PYCRYPTO:
            key = bytes(ql.mem.read(p["key"], p["key_len"])) if p["key"] else b""
            data = bytes(ql.mem.read(p["data"], p["data_len"])) if p["data"] else b""
            dig = _PHMAC.new(key, data, digestmod=digmod).digest()
        if p["out"]:
            ql.mem.write(p["out"], dig)
        _wr_u32(ql, p["out_len"], len(dig))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    _ret(ql, p["out"])


def PKCS5_PBKDF2_HMAC(ql: Qiling, hook_data):
    # (pass,passlen, salt,saltlen, iter, digest, keylen, out) -> 1
    p = ql.os.resolve_fcall_params(
        {"pw": POINTER, "pwlen": INT, "salt": POINTER, "saltlen": INT,
         "iters": INT, "digest": POINTER, "keylen": INT, "out": POINTER})
    try:
        pw = bytes(ql.mem.read(p["pw"], p["pwlen"])) if (p["pw"] and p["pwlen"]) else b""
        salt = bytes(ql.mem.read(p["salt"], p["saltlen"])) if (p["salt"] and p["saltlen"]) else b""
        hmod = {MD_SHA1: SHA1, MD_SHA256: SHA256, MD_SHA384: SHA384}.get(
            p["digest"], SHA256) if _HAVE_PYCRYPTO else None
        if _HAVE_PYCRYPTO:
            dk = PBKDF2(pw, salt, dkLen=p["keylen"], count=max(1, p["iters"]),
                        hmac_hash_module=hmod)
        else:
            dk = b"\x00" * p["keylen"]
        if p["out"]:
            ql.mem.write(p["out"], dk)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    _ret(ql, 1)


def RAND_bytes(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"buf": POINTER, "num": INT})
    try:
        data = get_random_bytes(p["num"]) if _HAVE_PYCRYPTO else b"\x00" * p["num"]
        if p["buf"] and p["num"]:
            ql.mem.write(p["buf"], data)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    _ret(ql, 1)


# ---------------------------------------------------------------------------
# asymmetric / ASN.1 family — pragmatic non-crashing stubs (NOT real crypto).
# These exist so RSA/EC/ASN.1 code paths proceed past the call instead of
# dying on default_func; flagged STUB in the log so verdicts don't trust them.
# ---------------------------------------------------------------------------
def _stub_handle(ql, hook_data, kind):
    h = _handle(ql, kind)
    _PKEY_OBJS[h] = kind
    ql.log.info(f"{hook_data.func_name} STUB -> handle {hex(h)} ({kind})")
    _ret(ql, h)


def _stub_ok(ql, hook_data):
    ql.log.info(f"{hook_data.func_name} STUB -> 1")
    _ret(ql, 1)


def _stub_void(ql, hook_data):
    ql.log.info(f"{hook_data.func_name} STUB (void)")
    _void(ql)


# EVP_PKEY / PKEY_CTX
def EVP_PKEY_new(ql, hook_data):              _stub_handle(ql, hook_data, "EVP_PKEY")
def EVP_PKEY_CTX_new(ql, hook_data):          _stub_handle(ql, hook_data, "EVP_PKEY_CTX")
def EVP_PKEY_CTX_free(ql, hook_data):         _stub_void(ql, hook_data)
def EVP_PKEY_CTX_set_rsa_keygen_bits(ql, h):  _stub_ok(ql, h)
def EVP_PKEY_CTX_set_rsa_mgf1_md(ql, h):      _stub_ok(ql, h)
def EVP_PKEY_CTX_set_rsa_oaep_md(ql, h):      _stub_ok(ql, h)
def EVP_PKEY_CTX_set_rsa_padding(ql, h):      _stub_ok(ql, h)
def EVP_PKEY_assign_EC_KEY(ql, h):            _stub_ok(ql, h)
def EVP_PKEY_get1_EC_KEY(ql, hook_data):      _stub_handle(ql, hook_data, "EC_KEY")
def EVP_PKEY_set_type(ql, h):                 _stub_ok(ql, h)
def EVP_PKEY_keygen_init(ql, h):              _stub_ok(ql, h)
def EVP_PKEY_sign_init(ql, h):                _stub_ok(ql, h)
def EVP_PKEY_encrypt_init(ql, h):             _stub_ok(ql, h)
def EVP_PKEY_decrypt_init(ql, h):             _stub_ok(ql, h)


def _pkey_outlen(ql, hook_data, default_len):
    # (ctx, out, *outlen, in, inlen): if out==NULL report a length; else fill.
    p = ql.os.resolve_fcall_params(
        {"ctx": POINTER, "out": POINTER, "outlen": POINTER,
         "inp": POINTER, "inlen": INT})
    try:
        if not p["out"]:
            _wr_u32(ql, p["outlen"], default_len)
        else:
            n = default_len
            if p["outlen"]:
                rd = ql.mem.read(p["outlen"], 4)
                n = min(default_len, int.from_bytes(rd, "little") or default_len)
            ql.mem.write(p["out"], b"\x00" * n)
            _wr_u32(ql, p["outlen"], n)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.log.info(f"{hook_data.func_name} STUB -> 1 (len {default_len})")
    _ret(ql, 1)


def EVP_PKEY_keygen(ql, hook_data):
    # (ctx, *ppkey): write a handle through ppkey if provided.
    p = ql.os.resolve_fcall_params({"ctx": POINTER, "ppkey": POINTER})
    h = _handle(ql, "EVP_PKEY")
    _PKEY_OBJS[h] = "EVP_PKEY"
    try:
        if p["ppkey"]:
            ql.mem.write_ptr(p["ppkey"], h)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    _ret(ql, 1)


def EVP_PKEY_sign(ql, hook_data):     _pkey_outlen(ql, hook_data, 256)
def EVP_PKEY_decrypt(ql, hook_data):  _pkey_outlen(ql, hook_data, 256)
def EVP_PKEY_encrypt(ql, hook_data):  _pkey_outlen(ql, hook_data, 256)


# EC_*
def EC_GROUP_new_by_curve_name(ql, hd): _stub_handle(ql, hd, "EC_GROUP")
def EC_GROUP_get_degree(ql, hook_data):
    ql.log.info("EC_GROUP_get_degree STUB -> 256")
    _ret(ql, 256)
def EC_KEY_new_by_curve_name(ql, hd):   _stub_handle(ql, hd, "EC_KEY")
def EC_KEY_set_public_key(ql, h):       _stub_ok(ql, h)
def EC_POINT_new(ql, hd):               _stub_handle(ql, hd, "EC_POINT")
def EC_POINT_oct2point(ql, h):          _stub_ok(ql, h)


# ASN.1
def ASN1_item_new(ql, hd):   _stub_handle(ql, hd, "ASN1_item")
def ASN1_item_free(ql, hd):  _stub_void(ql, hd)
def ASN1_item_d2i(ql, hd):   _stub_handle(ql, hd, "ASN1_item")
def ASN1_item_i2d(ql, hook_data):
    ql.log.info("ASN1_item_i2d STUB -> 0 length")
    _ret(ql, 0)
def ASN1_INTEGER_new(ql, hd):        _stub_handle(ql, hd, "ASN1_INTEGER")
def ASN1_INTEGER_free(ql, hd):       _stub_void(ql, hd)
def ASN1_INTEGER_set(ql, h):         _stub_ok(ql, h)
def ASN1_OCTET_STRING_new(ql, hd):   _stub_handle(ql, hd, "ASN1_OCTET_STRING")
def ASN1_OCTET_STRING_free(ql, hd):  _stub_void(ql, hd)
def ASN1_OCTET_STRING_set(ql, h):    _stub_ok(ql, h)
def ASN1_NULL_new(ql, hd):           _stub_handle(ql, hd, "ASN1_NULL")


# d2i / i2d
def d2i_PUBKEY(ql, hd):       _stub_handle(ql, hd, "EVP_PKEY")
def d2i_PrivateKey(ql, hd):   _stub_handle(ql, hd, "EVP_PKEY")
def i2d_PUBKEY(ql, hook_data):
    ql.log.info("i2d_PUBKEY STUB -> 0 length")
    _ret(ql, 0)
def i2d_PrivateKey(ql, hook_data):
    ql.log.info("i2d_PrivateKey STUB -> 0 length")
    _ret(ql, 0)
def i2d_PublicKey(ql, hook_data):
    ql.log.info("i2d_PublicKey STUB -> 0 length")
    _ret(ql, 0)


# ---------------------------------------------------------------------------
# BoringSSL error-queue helpers — void/no-op under emulation. Modelling these
# matters: TAs call ERR_print_errors_cb on a crypto failure (e.g. GCM tag
# mismatch), and leaving it unimplemented emu_stops mid-function, returning a
# garbage 64-bit PC that the harness then truncates with p32() -> struct.error.
# ---------------------------------------------------------------------------
def ERR_print_errors_cb(ql, hook_data):
    ql.log.info("ERR_print_errors_cb STUB (void)")
    _void(ql)


def ERR_clear_error(ql, hook_data):
    _void(ql)


def ERR_get_error(ql, hook_data):
    _ret(ql, 0)


def ERR_peek_error(ql, hook_data):
    _ret(ql, 0)


def ERR_print_errors_fp(ql, hook_data):
    _void(ql)


# ---------------------------------------------------------------------------
# X.509 / RSA / EC / ASN.1 verification family (Phase-3 asymmetric build-out).
# The cert-verification findings (engmod dev-CA accept, knxgud cert-purpose
# confusion, vltkpr VERIFY_CERT, fbckmr cmd 18 d2i_PUBKEY) sit *behind* these
# calls. We don't do real signature verification -- modelling the verify verbs
# as "success" and the d2i_* parsers as length-faithful handle factories lets
# the dispatcher reach the finding's accept/dispatch logic, which is the part
# the finding is about. Logged STUB; a verdict must not treat the verify as real.
# ---------------------------------------------------------------------------

def _d2i_advance(ql, hook_data, kind):
    # T *d2i_FOO(T **out, const unsigned char **inp, long len): return a handle,
    # write it through *out, and advance *inp past the consumed DER (length
    # faithful, so a caller looping over a buffer terminates).
    p = ql.os.resolve_fcall_params({"out": POINTER, "inp": POINTER, "length": INT})
    h = _handle(ql, kind)
    _PKEY_OBJS[h] = kind
    try:
        if p["inp"]:
            cur = ql.mem.read_ptr(p["inp"])
            ql.mem.write_ptr(p["inp"], cur + (p["length"] & 0xFFFFFFFF))
        if p["out"]:
            ql.mem.write_ptr(p["out"], h)
    except unicorn.unicorn_py3.unicorn.UcError:
        pass
    ql.log.info(f"{hook_data.func_name} STUB -> handle {hex(h)} ({kind})")
    _ret(ql, h)

def d2i_X509(ql, hd):           _d2i_advance(ql, hd, "X509")
def d2i_RSA_PUBKEY(ql, hd):     _d2i_advance(ql, hd, "RSA")
def d2i_RSAPublicKey(ql, hd):   _d2i_advance(ql, hd, "RSA")
def d2i_RSAPrivateKey(ql, hd):  _d2i_advance(ql, hd, "RSA")
def d2i_AutoPrivateKey(ql, hd): _d2i_advance(ql, hd, "EVP_PKEY")
def d2i_ECDSA_SIG(ql, hd):      _d2i_advance(ql, hd, "ECDSA_SIG")
def d2i_ECPrivateKey(ql, hd):   _d2i_advance(ql, hd, "EC_KEY")

def _i2d(ql, hook_data, default_len=0x400):
    # int i2d_FOO(T *a, unsigned char **out): return DER length; if out!=NULL
    # write that many bytes and advance *out.
    p = ql.os.resolve_fcall_params({"a": POINTER, "out": POINTER})
    n = default_len
    try:
        if p["out"]:
            outp = ql.mem.read_ptr(p["out"])
            if outp:
                ql.mem.write(outp, b"\x00" * n)
                ql.mem.write_ptr(p["out"], outp + n)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.log.info(f"{hook_data.func_name} STUB -> len {n}")
    _ret(ql, n)

def i2d_X509(ql, hd):           _i2d(ql, hd)
def i2d_RSAPublicKey(ql, hd):   _i2d(ql, hd)
def i2d_RSA_PUBKEY(ql, hd):     _i2d(ql, hd)
def i2d_ECDSA_SIG(ql, hd):      _i2d(ql, hd, 0x48)

# verification verbs -> success (1)
def X509_verify(ql, hd):             _stub_ok(ql, hd)
def X509_verify_cert(ql, hd):        _stub_ok(ql, hd)
def RSA_verify(ql, hd):              _stub_ok(ql, hd)
def ECDSA_verify(ql, hd):            _stub_ok(ql, hd)
def EVP_DigestVerifyInit(ql, hd):    _stub_ok(ql, hd)
def EVP_DigestVerifyUpdate(ql, hd):  _stub_ok(ql, hd)
def EVP_DigestVerifyFinal(ql, hd):   _stub_ok(ql, hd)
def EVP_DigestVerify(ql, hd):        _stub_ok(ql, hd)
def EVP_VerifyFinal(ql, hd):         _stub_ok(ql, hd)

# handle factories
def X509_get_pubkey(ql, hd):    _stub_handle(ql, hd, "EVP_PKEY")
def EVP_PKEY_get1_RSA(ql, hd):  _stub_handle(ql, hd, "RSA")
def RSA_new(ql, hd):            _stub_handle(ql, hd, "RSA")
def EC_KEY_new(ql, hd):         _stub_handle(ql, hd, "EC_KEY")
def PEM_read_bio_X509(ql, hd):  _stub_handle(ql, hd, "X509")
def PEM_read_bio_PUBKEY(ql, hd):_stub_handle(ql, hd, "EVP_PKEY")
def X509_STORE_new(ql, hd):     _stub_handle(ql, hd, "X509_STORE")
def X509_STORE_CTX_new(ql, hd): _stub_handle(ql, hd, "X509_STORE_CTX")

def BIO_new_mem_buf(ql, hook_data):
    # const handle wrapping the caller's buffer; we just hand back a token.
    _stub_handle(ql, hook_data, "BIO")

# free / setters -> void / ok
def X509_free(ql, hd):              _stub_void(ql, hd)
def RSA_free(ql, hd):               _stub_void(ql, hd)
def BIO_free(ql, hd):               _stub_void(ql, hd)
def X509_STORE_free(ql, hd):        _stub_void(ql, hd)
def X509_STORE_CTX_free(ql, hd):    _stub_void(ql, hd)
def X509_STORE_CTX_init(ql, hd):    _stub_ok(ql, hd)
def X509_STORE_add_cert(ql, hd):    _stub_ok(ql, hd)

def RSA_size(ql, hook_data):
    _ret(ql, 256)   # 2048-bit modulus

def _rsa_pub_op(ql, hook_data):
    # int RSA_public_{decrypt,encrypt}(int flen, const u8 *from, u8 *to,
    #                                  RSA *rsa, int padding) -> output length
    p = ql.os.resolve_fcall_params(
        {"flen": INT, "frm": POINTER, "to": POINTER, "rsa": POINTER, "padding": INT})
    n = min(max(p["flen"], 0), 512) or 256
    try:
        if p["to"]:
            ql.mem.write(p["to"], b"\x00" * n)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.log.info(f"{hook_data.func_name} STUB -> {n}")
    _ret(ql, n)

def RSA_public_decrypt(ql, hd):  _rsa_pub_op(ql, hd)
def RSA_public_encrypt(ql, hd):  _rsa_pub_op(ql, hd)
def RSA_private_decrypt(ql, hd): _rsa_pub_op(ql, hd)
def RSA_private_encrypt(ql, hd): _rsa_pub_op(ql, hd)

def ASN1_get_object(ql, hook_data):
    # int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
    #                     int *pclass, long omax)
    # Parse one DER TLV header at **pp: set *ptag/*pclass/*plength (content
    # length) and advance *pp past the identifier+length octets. Returns 0x20
    # (constructed), 0 (primitive) or 0x80 (error). A real-ish parse so a
    # hand-rolled DER reader (SEMeSE parseItemsFromGpCert, teessu cert_parcer)
    # walks the structure and can reach its own length-handling sink.
    p = ql.os.resolve_fcall_params(
        {"pp": POINTER, "plength": POINTER, "ptag": POINTER, "pclass": POINTER, "omax": INT})
    try:
        cur = ql.mem.read_ptr(p["pp"])
        omax = p["omax"] & 0xFFFFFFFFFFFFFFFF
        hdr = bytes(ql.mem.read(cur, max(1, min(omax, 16))))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    if not hdr:
        _ret(ql, 0x80)
        return
    tag0 = hdr[0]
    cls = (tag0 >> 6) & 0x3
    constructed = (tag0 >> 5) & 0x1
    tagnum = tag0 & 0x1F
    i = 1
    if tagnum == 0x1F:                       # high-tag-number form
        tagnum = 0
        while i < len(hdr) and (hdr[i] & 0x80):
            tagnum = (tagnum << 7) | (hdr[i] & 0x7F); i += 1
        if i < len(hdr):
            tagnum = (tagnum << 7) | (hdr[i] & 0x7F); i += 1
    if i >= len(hdr):
        _ret(ql, 0x80)
        return
    lb = hdr[i]; i += 1
    if lb & 0x80:                            # long-form length
        length = 0
        for _ in range(lb & 0x7F):
            if i >= len(hdr):
                break
            length = (length << 8) | hdr[i]; i += 1
    else:
        length = lb
    try:
        ql.mem.write_ptr(p["pp"], cur + i)
        if p["plength"]:
            ql.mem.write_ptr(p["plength"], length & 0xFFFFFFFFFFFFFFFF)
        if p["ptag"]:
            _wr_u32(ql, p["ptag"], tagnum)
        if p["pclass"]:
            _wr_u32(ql, p["pclass"], cls << 6)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ret = 0x20 if constructed else 0
    ql.log.info(f"ASN1_get_object tag={tagnum} len={length} cls={cls} -> {ret}")
    _ret(ql, ret)
