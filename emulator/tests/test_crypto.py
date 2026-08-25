"""Known-answer tests for the emulator's crypto reimplementations
(emulate/gp/utils/crypto.py + bigint.py).

These exercise the CUSTOM glue around pycryptodome -- the no-pad block handling,
the operation lifecycle (init/activate/update/finalize), the RSA key marshaling,
the two's-complement bigint bounds -- which is exactly the code most likely to
silently diverge from the GP spec and produce false findings (Tier 4.11). The
Operation classes take a `ql` only for logging, so a tiny fake suffices.

Run from emulator/ inside ta_emu:
    python3 -m pytest tests/test_crypto.py      (or: python3 tests/test_crypto.py)
"""
import binascii
import os
import sys

# make the `emulate` package importable regardless of how this is invoked
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from emulate.gp.utils import crypto as C
from emulate.gp.utils import bigint as B


class _Log:
    def info(self, *a, **k):
        pass

    error = warning = debug = info


class FakeQL:
    log = _Log()

    def emu_stop(self):
        raise AssertionError("emu_stop() called -- operation hit an error path")


ql = FakeQL()
_hx = lambda b: binascii.hexlify(b)
_un = binascii.unhexlify


def test_sha256_kat():
    # FIPS 180-4: SHA256("abc")
    op = C.Digest_Operation(0, ql)
    assert _hx(op.finalize(b"abc", 32, ql)) == \
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_streaming_matches_oneshot():
    op = C.Digest_Operation(0, ql)
    op.digest_update(b"a")
    op.digest_update(b"b")
    assert _hx(op.finalize(b"c", 32, ql)).startswith(b"ba7816bf")


def test_sha256_finalize_rejects_short_buffer():
    # hash_len smaller than the digest must return None, not truncate silently
    op = C.Digest_Operation(0, ql)
    assert op.finalize(b"abc", 16, ql) is None


def test_md5_kat():
    op = C.MD5_Operation(0, ql)
    assert _hx(op.finalize(b"abc", 16, ql)) == b"900150983cd24fb0d6963f7d28e17f72"


def test_aes128_ecb_fips197_kat():
    key = _un("000102030405060708090a0b0c0d0e0f")
    pt = _un("00112233445566778899aabbccddeeff")
    op = C.AES_ECB_NOPAD_Operation(0, C.TEE_MODE_ENCRYPT, ql)
    op.initialize(key, ql)
    op.activate(b"")
    assert _hx(op.finalize(pt)) == b"69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes128_cbc_roundtrip():
    key, iv = b"\x00" * 16, b"\x01" * 16
    pt = b"0123456789abcdef"  # one block (no-pad: keep block-aligned)
    enc = C.AES_CBC_NOPAD_Operation(0, C.TEE_MODE_ENCRYPT, ql)
    enc.initialize(key, ql); enc.activate(iv)
    ct = enc.finalize(pt)
    dec = C.AES_CBC_NOPAD_Operation(0, C.TEE_MODE_DECRYPT, ql)
    dec.initialize(key, ql); dec.activate(iv)
    assert dec.finalize(ct) == pt
    assert ct != pt


def test_hmac_sha256_rfc4231_case2():
    op = C.TEE_ALG_HMAC_SHA256_Operation(0, C.TEE_MODE_SIGN, ql)
    op.initialize(b"Jefe", ql)
    op.activate()
    mac = op.compute(b"what do ya want for nothing?")
    assert _hx(mac) == \
        b"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_rsa_pkcs1_v15_decrypt_roundtrip():
    from Crypto.PublicKey import RSA as _RSA
    from Crypto.Cipher import PKCS1_v1_5 as _P
    from Crypto.Util.number import long_to_bytes
    k = _RSA.generate(1024)
    msg = b"difftest-secret"
    ct = _P.new(k.publickey()).encrypt(msg)
    op = C.RSAES_PKCS1_V1_5_Operation(0, C.TEE_MODE_DECRYPT, 1024, ql)
    op.initialize(
        {"n": long_to_bytes(k.n), "d": long_to_bytes(k.d), "e": long_to_bytes(k.e)}, ql
    )
    assert op.decrypt(ct, ql) == msg


def test_bigint_fits_in_twos_complement():
    assert B.fits_in(127, 1) is True
    assert B.fits_in(128, 1) is False
    assert B.fits_in(-128, 1) is True
    assert B.fits_in(-129, 1) is False
    assert B.fits_in(32767, 2) is True
    assert B.fits_in(-32769, 2) is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
