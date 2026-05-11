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
]

BIGVAL_WORDS = 0x12
BIGVAL_SIZE = BIGVAL_WORDS * 4  # 0x48 == 72 bytes
ECC_BINARY_SIZE = 32
MAX_STUB_WRITE_SIZE = 0x1000


def _known_bytes(seed: int, size: int) -> bytes:
    return bytes((seed + i) & 0xff for i in range(size))


def _bigval_from_binary(data: bytes, seed: int = 0) -> bytes:
    """
    QSEE bigvals are larger than common 256-bit ECC scalars. For emulation,
    preserve up to 32 input bytes at the start and make the whole bigval
    initialized so later exports/readbacks see deterministic data.
    """
    scalar = data[:ECC_BINARY_SIZE].ljust(ECC_BINARY_SIZE, b"\x00")
    padding = _known_bytes(seed, BIGVAL_SIZE - ECC_BINARY_SIZE)
    return scalar + padding


def _write_if_nonzero(ql: Qiling, ptr: int, data: bytes):
    if ptr:
        ql.mem.write(ptr, data)


def _write_bigval(ql: Qiling, ptr: int, seed: int):
    _write_if_nonzero(ql, ptr, _bigval_from_binary(_known_bytes(seed, ECC_BINARY_SIZE), seed + ECC_BINARY_SIZE))


def _write_binary(ql: Qiling, ptr: int, seed: int, size: int = ECC_BINARY_SIZE):
    _write_if_nonzero(ql, ptr, _known_bytes(seed, min(size, MAX_STUB_WRITE_SIZE)))


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
    _write_binary(ql, args["sig_r"], 0x10)
    _write_binary(ql, args["sig_s"], 0x30)

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
    data = ql.mem.read(args["src_bin"], src_len) if args["src_bin"] and src_len else b""

    if args["dst_bigval"]:
        ql.mem.write(args["dst_bigval"], _bigval_from_binary(data, 0xd0))

    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_bigval_to_binary(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "src_bigval": POINTER,
        "out_len": INT,
        "out_bin": POINTER,
        "ctx": POINTER,
    })

    _log_args(ql, "qsee_SW_GENERIC_ECC_bigval_to_binary", args)

    data = ql.mem.read(args["src_bigval"], ECC_BINARY_SIZE) if args["src_bigval"] else _known_bytes(0xf0, ECC_BINARY_SIZE)

    _write_if_nonzero(ql, args["out_bin"], data)
    if args["out_len"]:
        ql.mem.write_ptr(args["out_len"], len(data))

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
    data = ql.mem.read(args["src_bin"], src_len) if args["src_bin"] and src_len else b""

    _write_if_nonzero(ql, args["dst_bigval"], _bigval_from_binary(data, 0xd0))

    _ret(ql, 0)


def qsee_SW_GENERIC_ECC_affine_point_on_curve(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "point_x": POINTER,
        "point_y": POINTER,
    })
    _log_args(ql, "qsee_SW_GENERIC_ECC_affine_point_on_curve", args)

    # Return boolean
    _ret(ql, 1)
