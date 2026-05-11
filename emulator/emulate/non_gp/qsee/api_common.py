import functools
from qiling import Qiling
import struct


def _wrap_fcall_with_debug_log(func):
    @functools.wraps(func)
    def wrapper(ql: Qiling, hook_data):
        ql.log.info("Called func: %s", hook_data.func_name)
        ql.log.info("Ret ptr: %#x", ql.arch.regs.lr)
        val = func(ql, hook_data)
        ql.log.info("Returned value: %s", val)
    return wrapper

def _ret(ql: Qiling, value: int):
    ql.os.fcall.cc.setReturnValue(value)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def _read_u32(ql: Qiling, ptr: int) -> int:
    return struct.unpack("<I", ql.mem.read(ptr, 4))[0] & 0xffffffff
