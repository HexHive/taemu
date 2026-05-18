import hashlib
import pwn
from qiling import Qiling
from qiling.os.const import INT, POINTER

from typing import TYPE_CHECKING

from emulate.non_gp.qsee.models import get_active_qsee_session_state
from .api_common import _ret, _log_args

if TYPE_CHECKING:
    from emulate.emulator_no_loader import HookData
    from emulate.ta_mgr import TAEMU


BIGVAL_WORDS = 0x12
BIGVAL_SIZE = BIGVAL_WORDS * 4  # 0x48 == 72 bytes
ECC_BINARY_SIZE = 32
MAX_STUB_WRITE_SIZE = 0x1000
HASH_DIGEST_SIZE = 32
HASH_SEGMENT_SIZE = 0x10
HASH_MAX_SEGMENTS = 0x100
HASH_MAX_DIGEST_WRITE = 0x100


def marker_bytes(seed: int, size: int) -> bytes:
    return bytes((seed + i) & 0xff for i in range(size))


def _bigval_from_binary(data: bytes, seed: int = 0) -> bytes:
    value = int.from_bytes(data, "big")
    if value == 0:
        value = int.from_bytes(marker_bytes(seed, ECC_BINARY_SIZE), "big")
    return value.to_bytes(BIGVAL_SIZE, "little")


def _bigval_to_binary(data: bytes, out_len: int) -> bytes:
    value = int.from_bytes(data, "little")
    return value.to_bytes(BIGVAL_SIZE, "big")[-out_len:]


def _write_bigval(ql: Qiling, ptr: int, seed: int):
    ql.mem.write(ptr, _bigval_from_binary(marker_bytes(seed, ECC_BINARY_SIZE), seed))



def _write_binary_struct(ql: Qiling, ptr: int, seed: int, size: int = ECC_BINARY_SIZE):
    data = marker_bytes(seed, min(size, MAX_STUB_WRITE_SIZE))
    out_ptr = ql.mem.read_ptr(ptr)
    ql.mem.write(out_ptr, data)
    ql.mem.write_ptr(ptr + ql.arch.pointersize, len(data))


def _read_ptr(ql: Qiling, ptr: int) -> int:
    return ql.mem.read_ptr(ptr)


def _read_u32(ql: Qiling, ptr: int) -> int:
    return int.from_bytes(ql.mem.read(ptr, 4), "little")


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
    qss = get_active_qsee_session_state(hook_data.emu)
    ref = qss.reserve_exec_ref_slot()
    noop_ref = qss.register_named_noop(ql, hook_data.emu, name=f"qsee_SW_Hash_Init_{ref:x}", singleton_key=f"qsee_SW_Hash_Init_{ref:x}")
    ql.mem.write_ptr(args["ctx_out"], noop_ref)
    _ret(ql, 0)


def qsee_SW_Hash_Update(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "segments": POINTER,
        "segment_count": INT,
    })
    _log_args(ql, "qsee_SW_Hash_Update", args)
    _ret(ql, 0)


def qsee_SW_Hash_Final(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "out": POINTER,
    })
    _log_args(ql, "qsee_SW_Hash_Final", args)

    ql.mem.write(args["out"], marker_bytes(0x63, 0x10))
    _ret(ql, 0)


def qsee_SW_Hash_Deinit(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx_ptr": POINTER,
    })
    _log_args(ql, "qsee_SW_Hash_Deinit", args)
    _ret(ql, 0)


def qsee_SW_Hash_Reset(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
    })
    _log_args(ql, "qsee_SW_Hash_Reset", args)
    _ret(ql, 0)


def qsee_SW_Hash_SetParam(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "param_id": INT,
        "param": POINTER,
        "param_len": INT,
        "alg": INT,
    })
    param = ql.mem.read(args["param"], args["param_len"])
    ql.log.info("qsee_SW_Hash_SetParam(ctx=&%#x, param_id=%#x, param='%s')", args["ctx"], args["param_id"], param)

    _ret(ql, 0)

# # TODO: REmove, this one doesn't exist in the stdlib I have
# def qsee_SW_Hash(ql: Qiling, hook_data: "HookData"):
#     args = ql.os.resolve_fcall_params({
#         "input": POINTER,
#         "input_len": INT,
#         "segments": POINTER,
#         "segment_count": INT,
#         "out": POINTER,
#         "alg": INT,
#     })
#     _log_args(ql, "qsee_SW_Hash", args)

#     ql.mem.write(args["out"], marker_bytes(0x61, args["out_len"]))
#     _ret(ql, 0)

def qsee_hash_init(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "algo": INT,
        "ctx_out": POINTER,
    })
    ql.log.warning("USING NOPPED CRYPTO:")
    _log_args(ql, "qsee_hash_init", args)
    ctx_out = args["ctx_out"]

    if not ctx_out:
        _ret(ql, 1)
        return

    qss = get_active_qsee_session_state(hook_data.emu)
    ref = qss.reserve_exec_ref_slot()
    noop_ref = qss.register_named_noop(ql, hook_data.emu, name=f"qsee_hash_ctx_{ref:x}", singleton_key=f"qsee_hash_ctx_{ref:x}")

    # Real ctx is two p64:
    #   ctx + 0x00: function ?
    #   ctx + 0x08: fake "self" ptr
    ql.mem.write_ptr(ref, noop_ref)
    ql.mem.write_ptr(ctx_out, ref)
    _ret(ql, 0)


def qsee_hash_update(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "data": POINTER,
        "data_len": INT,
    })

    data = ql.mem.read(args["data"], args["data_len"])
    ctx = ql.mem.read_ptr(args["ctx"])
    ql.log.warning("USING NOPPED CRYPTO:")
    ql.log.info("qsee_hash_update(ctx=&%#x, data(ptr+len)=%s)", ctx, data)

    _ret(ql, 0)


def qsee_hash_final(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "out_digest": POINTER,
        "out_len": INT,
    })

    ctx = ql.mem.read_ptr(args["ctx"])
    ql.log.warning("USING NOPPED CRYPTO:")
    ql.log.info("qsee_hash_final(ctx=&%#x, out_digest=&%#x, out_len=%#x)", ctx, args["out_digest"], args["out_len"])

    digest = marker_bytes(0x62, args["out_len"])
    
    ql.mem.write(args["out_digest"], digest)
    _ret(ql, 0)


def qsee_hash_free_ctx(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
    })

    ctx = ql.mem.read_ptr(args["ctx"])
    ql.log.warning("USING NOPPED CRYPTO:")
    ql.log.info("qsee_hash_free_ctx(ctx=&%#x)", ctx)
    _ret(ql, 0)


def qsee_hash_reset(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
    })

    ctx = ql.mem.read_ptr(args["ctx"])
    ql.log.warning("USING NOPPED CRYPTO:")
    ql.log.info("qsee_hash_reset(ctx=&%#x)", ctx)
    _ret(ql, 0)


def qsee_hash_set_param(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "param_id": INT,
        "value": POINTER,
        "value_len": INT,
    })

    ctx = ql.mem.read_ptr(args["ctx"])
    value = ql.mem.read(args["value"], args["value_len"])
    param_id = args["param_id"]

    ql.log.warning("USING NOPPED CRYPTO:")
    ql.log.info("qsee_hash_set_param(ctx=&%#x, param_id=%#x, value='%s')", ctx, param_id, value)

    _ret(ql, 0)

QSEE_HASH_ALGS = {
    1: ("sha1",   hashlib.sha1), # 20
    2: ("sha256", hashlib.sha256), # 32
    3: ("sha384", hashlib.sha384), # 48
    4: ("sha512", hashlib.sha512), # 64
    
    # 100% sure
    5: ("sha224", hashlib.sha224), # 28
}
def qsee_hash(ql: Qiling, hook_data: "HookData"):
    # Return is "is_error" styled
    args = ql.os.resolve_fcall_params({
        "algo": INT,
        "data": POINTER,
        "data_len": INT,
        "out_digest": POINTER,
        "out_len": POINTER,
    })
    data = ql.mem.read(args["data"], args["data_len"])
    ql.log.info("qsee_hash(algo=%#x, data(ptr+len)=%s), dest=%#x", args["algo"], data, args["out_digest"])

    algo = args["algo"]
    if algo not in QSEE_HASH_ALGS:
        ql.log.warning("qsee_hash: invalid algo %#x", algo)
        return _ret(ql, 1)
    
    name, fn = QSEE_HASH_ALGS[algo]
    ql.log.debug("qsee_hash: using %s", name)
    digest = fn(data).digest()

    ql.mem.write(args["out_digest"], digest)
    ql.mem.write(args["out_len"], pwn.p32(len(digest)))
    _ret(ql, 0)
