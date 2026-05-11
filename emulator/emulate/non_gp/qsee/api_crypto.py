from qiling import Qiling
from qiling.os.const import INT, POINTER

from typing import TYPE_CHECKING
from .api_common import _ret

if TYPE_CHECKING:
    from emulate.emulator_no_loader import HookData
    from emulate.ta_mgr import TAEMU


__all__ = [
    "qsee_SW_GENERIC_ECC_init",
    "qsee_SW_GENERIC_ECDSA_sign_ex",
    "qsee_SW_GENERIC_ECDSA_sign",
    "qsee_SW_GENERIC_ECDSA_verify_ex",
    "qsee_SW_GENERIC_ECDSA_verify",
    "qsee_SW_GENERIC_ECDH_shared_key_derive",
    "qsee_SW_GENERIC_ECC_keypair_generate",
    "qsee_SW_GENERIC_ECC_pubkey_generate",
    "qsee_SW_GENERIC_ECC_binary_to_bigval",
    "qsee_SW_GENERIC_ECC_bigval_to_binary",
    "qsee_SW_GENERIC_ECC_compare",
    "qsee_SW_GENERIC_ECC_convert_input_to_bigval",
    "qsee_SW_GENERIC_ECC_affine_point_on_curve",
    "qsee_SW_Hash_Init",
    "qsee_SW_Hash_Update",
    "qsee_SW_Hash_Final",
    "qsee_SW_Hash_Deinit",
    "qsee_SW_Hash_Reset",
    "qsee_SW_Hash_SetParam",
    "qsee_SW_Hash",
]

BIGVAL_WORDS = 0x12
BIGVAL_SIZE = BIGVAL_WORDS * 4  # 0x48 == 72 bytes
ECC_BINARY_SIZE = 32
MAX_STUB_WRITE_SIZE = 0x1000
HASH_DIGEST_SIZE = 32
HASH_SEGMENT_SIZE = 0x10
HASH_MAX_SEGMENTS = 0x100
HASH_MAX_DIGEST_WRITE = 0x100


def _known_bytes(seed: int, size: int) -> bytes:
    return bytes((seed + i) & 0xff for i in range(size))


def _bigval_from_binary(data: bytes, seed: int = 0) -> bytes:
    value = int.from_bytes(data, "big")
    if value == 0:
        value = int.from_bytes(_known_bytes(seed, ECC_BINARY_SIZE), "big")
    return value.to_bytes(BIGVAL_SIZE, "little")


def _bigval_to_binary(data: bytes, out_len: int) -> bytes:
    value = int.from_bytes(data, "little")
    return value.to_bytes(BIGVAL_SIZE, "big")[-out_len:]


def _write_bytes(ql: Qiling, ptr: int, data: bytes):
    ql.mem.write(ptr, data)


def _write_bigval(ql: Qiling, ptr: int, seed: int):
    _write_bytes(ql, ptr, _bigval_from_binary(_known_bytes(seed, ECC_BINARY_SIZE), seed))


def _write_binary(ql: Qiling, ptr: int, seed: int, size: int = ECC_BINARY_SIZE):
    _write_bytes(ql, ptr, _known_bytes(seed, min(size, MAX_STUB_WRITE_SIZE)))


def _write_binary_struct(ql: Qiling, ptr: int, seed: int, size: int = ECC_BINARY_SIZE):
    data = _known_bytes(seed, min(size, MAX_STUB_WRITE_SIZE))
    out_ptr = _read_ptr(ql, ptr)
    _write_bytes(ql, out_ptr, data)
    _write_ptr(ql, ptr + ql.arch.pointersize, len(data))


def _read_bytes(ql: Qiling, ptr: int, size: int) -> bytes:
    return ql.mem.read(ptr, size)


def _read_ptr(ql: Qiling, ptr: int) -> int:
    return ql.mem.read_ptr(ptr)


def _read_u32(ql: Qiling, ptr: int) -> int:
    return int.from_bytes(_read_bytes(ql, ptr, 4), "little")


def _write_ptr(ql: Qiling, ptr: int, value: int):
    ql.mem.write_ptr(ptr, value)


def _hash_contexts(ql: Qiling) -> dict:
    if not hasattr(ql, "_qsee_hash_contexts"):
        ql._qsee_hash_contexts = {}
        ql._qsee_next_hash_ctx = 0x51480000
    return ql._qsee_hash_contexts


def _new_hash_context(ql: Qiling, alg: int) -> int:
    contexts = _hash_contexts(ql)
    handle = ql._qsee_next_hash_ctx
    ql._qsee_next_hash_ctx += 0x10
    contexts[handle] = {"alg": alg, "updated": 0}
    return handle


def _hash_digest(size: int = HASH_DIGEST_SIZE) -> bytes:
    return _known_bytes(0xa0, min(size, HASH_MAX_DIGEST_WRITE))


def _remember_hash_update(ql: Qiling, ctx: int, segments: int):
    contexts = _hash_contexts(ql)
    contexts.setdefault(ctx, {"alg": 0, "updated": 0})["updated"] += segments


def _write_hash_segment(ql: Qiling, segment_ptr: int) -> bool:
    out_ptr = _read_ptr(ql, segment_ptr)
    out_len = _read_u32(ql, segment_ptr + ql.arch.pointersize)
    size = out_len or HASH_DIGEST_SIZE
    _write_bytes(ql, out_ptr, _hash_digest(size))
    ql.mem.write_ptr(segment_ptr + ql.arch.pointersize, min(size, HASH_MAX_DIGEST_WRITE))
    return True


def _write_hash_output(ql: Qiling, out: int) -> bool:
    segments = _read_ptr(ql, out)
    _read_u32(ql, out + ql.arch.pointersize)
    return _write_hash_segment(ql, segments)


def _log_args(ql: Qiling, name: str, args: dict):
    ql.log.info(
        "%s(%s), back to %#x",
        name,
        ", ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}" for k, v in args.items()),
        ql.arch.regs.lr,
    )


def qsee_SW_GENERIC_ECC_init(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "curve": INT,
        "generator_x": POINTER,
        "generator_y": POINTER,
        "order": POINTER,
        "modulus": POINTER,
        "mont_r": POINTER,
        "mont_rr": POINTER,
        "flags": INT,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECC_init", args)
    _ret(ql, 0)


def qsee_SW_GENERIC_ECDSA_sign_ex(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "curve": INT,
        "priv_key_bin": POINTER,
        "priv_key_len": INT,
        "digest": POINTER,
        "sig_r": POINTER,
        "sig_s": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECDSA_sign_ex", args)

    # _ex takes binary key material and returns binary signature components.
    _write_binary_struct(ql, args["sig_r"], 0x10)
    _write_binary_struct(ql, args["sig_s"], 0x30)

    _ret(ql, 0)


def qsee_SW_GENERIC_ECDSA_sign(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "priv_key_bigval": POINTER,
        "key_size": INT,
        "digest": POINTER,
        "sig_r": POINTER,
        "sig_s": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECDSA_sign", args)

    # Non-_ex APIs use QSEE bigval objects for scalars.
    _write_bigval(ql, args["sig_r"], 0x10)
    _write_bigval(ql, args["sig_s"], 0x30)

    _ret(ql, 0)


def qsee_SW_GENERIC_ECDSA_verify_ex(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "curve": INT,
        "pub_key_bin": POINTER,
        "pub_key_len": INT,
        "digest": POINTER,
        "sig_r": POINTER,
        "sig_s": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECDSA_verify_ex", args)

    # Pretend signature is valid.
    _ret(ql, 0)


def qsee_SW_GENERIC_ECDSA_verify(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "pub_key_bigval": POINTER,
        "key_size": INT,
        "digest": POINTER,
        "sig_r": POINTER,
        "sig_s": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECDSA_verify", args)

    # Pretend signature is valid.
    _ret(ql, 0)


def qsee_SW_GENERIC_ECDH_shared_key_derive(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "priv_key": POINTER,
        "pub_key_x": POINTER,
        "pub_key_y": POINTER,
        "shared_key": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECDH_shared_key_derive", args)

    _write_bigval(ql, args["shared_key"], 0x50)

    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_keypair_generate(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "priv_key": POINTER,
        "pub_key_x": POINTER,
        "pub_key_y": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECC_keypair_generate", args)

    _write_bigval(ql, args["priv_key"], 0x70)
    _write_bigval(ql, args["pub_key_x"], 0x90)
    _write_bigval(ql, args["pub_key_y"], 0xb0)

    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_pubkey_generate(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "priv_key": POINTER,
        "pub_key_x": POINTER,
        "pub_key_y": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECC_pubkey_generate", args)

    _write_bigval(ql, args["pub_key_x"], 0x90)
    _write_bigval(ql, args["pub_key_y"], 0xb0)
    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_binary_to_bigval(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "dst_bigval": POINTER,
        "src_bin": POINTER,
        "src_len": INT,
        "ctx": POINTER,
        "curve_or_mode": INT,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECC_binary_to_bigval", args)

    src_len = min(args["src_len"], MAX_STUB_WRITE_SIZE)
    data = ql.mem.read(args["src_bin"], src_len)
    ql.mem.write(args["dst_bigval"], _bigval_from_binary(data, 0xd0))

    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_bigval_to_binary(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "out_bin": POINTER,
        "out_len": INT,
        "src_bigval": POINTER,
        "ctx": POINTER,
        "curve_or_mode": INT,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECC_bigval_to_binary", args)
    data = _bigval_to_binary(ql.mem.read(args["src_bigval"], BIGVAL_SIZE), args["out_len"])

    ql.mem.write(args["out_bin"], data)

    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_compare(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "a": POINTER,
        "b": POINTER,
        "ctx": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECC_compare", args)

    # Equal.
    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_convert_input_to_bigval(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "dst_bigval": POINTER,
        "src_bin": POINTER,
        "src_len": INT,
    })
    _log_args(ql, "qsee_SW_GENERIC_ECC_convert_input_to_bigval", args)

    src_len = min(args["src_len"], MAX_STUB_WRITE_SIZE)
    data = ql.mem.read(args["src_bin"], src_len)

    ql.mem.write(args["dst_bigval"], _bigval_from_binary(data, 0xd0))

    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_affine_point_on_curve(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "point_x": POINTER,
        "point_y": POINTER,
    })
    _log_args(ql, "qsee_SW_GENERIC_ECC_affine_point_on_curve", args)

    # Return boolean
    _ret(ql, 1)


def qsee_SW_Hash_Init(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx_out": POINTER,
        "alg": INT,
    })
    _log_args(ql, "qsee_SW_Hash_Init", args)

    handle = _new_hash_context(ql, args["alg"])
    _write_ptr(ql, args["ctx_out"], handle)

    _ret(ql, 0)


def qsee_SW_Hash_Update(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "segments": POINTER,
        "segment_count": INT,
    })
    _log_args(ql, "qsee_SW_Hash_Update", args)

    segment_count = min(args["segment_count"], HASH_MAX_SEGMENTS)
    for i in range(segment_count):
        segment = args["segments"] + i * HASH_SEGMENT_SIZE
        data_ptr = _read_ptr(ql, segment)
        data_len = _read_u32(ql, segment + ql.arch.pointersize)
        _read_bytes(ql, data_ptr, min(data_len, MAX_STUB_WRITE_SIZE))
    _remember_hash_update(ql, args["ctx"], segment_count)

    _ret(ql, 0)


def qsee_SW_Hash_Final(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "out": POINTER,
    })
    _log_args(ql, "qsee_SW_Hash_Final", args)

    _write_hash_output(ql, args["out"])

    _ret(ql, 0)


def qsee_SW_Hash_Deinit(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx_ptr": POINTER,
    })
    _log_args(ql, "qsee_SW_Hash_Deinit", args)

    contexts = _hash_contexts(ql)
    ctx = _read_ptr(ql, args["ctx_ptr"])
    contexts.pop(ctx, None)
    contexts.pop(args["ctx_ptr"], None)
    _write_ptr(ql, args["ctx_ptr"], 0)

    _ret(ql, 0)


def qsee_SW_Hash_Reset(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
    })
    _log_args(ql, "qsee_SW_Hash_Reset", args)

    contexts = _hash_contexts(ql)
    contexts[args["ctx"]]["updated"] = 0

    _ret(ql, 0)


def qsee_SW_Hash_SetParam(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "param_id": INT,
        "param": POINTER,
        "param_len": INT,
        "alg": INT,
    })
    _log_args(ql, "qsee_SW_Hash_SetParam", args)

    _read_bytes(ql, args["param"], min(args["param_len"], MAX_STUB_WRITE_SIZE))

    _ret(ql, 0)


def qsee_SW_Hash(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "input": POINTER,
        "input_len": INT,
        "segments": POINTER,
        "segment_count": INT,
        "out": POINTER,
        "alg": INT,
    })
    _log_args(ql, "qsee_SW_Hash", args)

    _read_bytes(ql, args["input"], min(args["input_len"], MAX_STUB_WRITE_SIZE))
    segment_count = min(args["segment_count"], HASH_MAX_SEGMENTS)
    for i in range(segment_count):
        segment = args["segments"] + i * HASH_SEGMENT_SIZE
        data_ptr = _read_ptr(ql, segment)
        data_len = _read_u32(ql, segment + ql.arch.pointersize)
        _read_bytes(ql, data_ptr, min(data_len, MAX_STUB_WRITE_SIZE))
    _write_hash_output(ql, args["out"])

    _ret(ql, 0)
