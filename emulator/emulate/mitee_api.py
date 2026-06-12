from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp.session import TEE_OpenTASession
from .determinism import get_random_bytes, now as _det_now
from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE
import time as pytime
from .common import crash

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf, TEE_MemCompare, malloc, free


def zx_check_memory_access_rights(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    out = ql.os.resolve_fcall_params(
        {"perm": INT, "buf": POINTER, "size": POINTER, "out": POINTER}
    )["out"]
    ql.os.fcall.cc.setReturnValue(0)
    ql.mem.write(out, (0).to_bytes(4, "little"))
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def consttime_memcmp(ql: Qiling, hook_data):
    TEE_MemCompare(ql, hook_data)


def time(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(_det_now())
    ql.arch.regs.arch_pc = ql.arch.regs.lr


KMHMACKEY = 0x20 * b"A"


def TEE_KMGetHmacKey(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"buf": POINTER, "size": INT})
    buf = params["buf"]
    size = params["size"]
    try:
        ql.mem.write(buf, KMHMACKEY)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(buf, size)
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def OPENSSL_memory_alloc(ql: Qiling, hook_data):
    malloc(ql, hook_data)


def OPENSSL_memory_free(ql: Qiling, hook_data):
    free(ql, hook_data)


def localtime(ql: Qiling, hook_data):
    t = ql.mem.map_anywhere(9 * 4)
    ql.os.fcall.cc.setReturnValue(t)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def soter_load_fingerprint_result(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"buf": POINTER, "fp_type": INT})
    buf = params["buf"]
    fp_type = params["fp_type"]
    out = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046696e6765727072696e74204361726473000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ql.mem.write(buf, bytes.fromhex(out))
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def tee_get_cpuid(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
