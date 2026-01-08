from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp_api import malloc
from .common import crash, crash_notimpl
from .gp.utils.printf import parse_fmt_str, fixup_format, read_c_str

def optee_syscall(ql: Qiling, intno, emu):
    syscall_nr = ql.arch.regs.x8
    ql.log.info(f"[optee] syscall {syscall_nr}")
    if syscall_nr == 1:
        # logging
        buf = ql.arch.regs.x0 
        len = ql.arch.regs.x1
        out = ql.mem.read(buf, len).decode('utf-8', errors='replace')
        ql.log.info(f"[optee log] {out}")
    elif syscall_nr == 2:
        ql.emu_stop()
        return
    else:
        ql.log.info(f"syscall {syscall_nr} not implemented")
        if emu.crash_on_not_implemented:
            crash_notimpl(ql, f"optee syscall not implemented")
            return
        else:
            ql.emu_stop()
            return

"""
def qsee_is_sw_fuse_blown(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
            {"idk": INT, "out": POINTER}
        )
    ql.mem.write(p["out"], 4*b"\x00")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
"""