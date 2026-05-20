from collections import defaultdict
import functools
from typing import TYPE_CHECKING
from qiling import Qiling
import struct

if TYPE_CHECKING:
    from emulate.non_gp.qsee.models import HookData
    from emulate.ta_mgr import TAEMU


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

def _log_args(ql: Qiling, name: str, args: dict):
    ql.log.info(
        "%s(%s), back to %#x",
        name,
        ", ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}" for k, v in args.items()),
        ql.arch.regs.lr,
    )

def nonfaithful(func):
    @functools.wraps(func)
    def wrapper(ql: Qiling, hook_data: 'HookData'):
        arm_instruction_size = 0x4
        ql.log.warning("Non-faithful call to %s from %#x", hook_data.func_name, ql.arch.regs.lr - arm_instruction_size)
        d = getattr(hook_data.emu, '__nonfaithful_frequency', None)
        if d is None:
            d = hook_data.emu.__nonfaithful_frequency = defaultdict(int)
        d[hook_data.func_name] += 1
        return func(ql, hook_data)
    return wrapper

def emu_report_nonfaithful(emu: 'TAEMU'):
    d = getattr(emu, '__nonfaithful_frequency', defaultdict(int))
    for func_name, count in d.items():
        emu.ql.log.warning("Non-faithful call to %s: %d times", func_name, count)