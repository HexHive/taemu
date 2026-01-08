from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp_api import malloc
from .common import crash, crash_notimpl
from .gp.utils.printf import parse_fmt_str, fixup_format, read_c_str

def qsee_is_sw_fuse_blown(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
            {"idk": INT, "out": POINTER}
        )
    ql.mem.write(p["out"], 4*b"\x00")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_log_set_mask(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_log(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params(
            {"log_level": INT, "format": POINTER}
        )
        log_level = p["log_level"]
        format_param_ptr = p["format"]
        hook_data.emu.update_shm(format_param_ptr)
        format_param = ql.mem.string(format_param_ptr)
        final_params = {"log_level": INT, "format": STRING}
        params = parse_fmt_str(ql, format_param, final_params, hook_data.func_name)
        format_param = fixup_format(format_param)
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        try:
            out_str = format_param % tuple(string_params)
        except TypeError:
            ql.log.error(f"format string not supported: {format_param}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"format string not supported: {format_param}")
                return
        ql.log.info(f"{hook_data.func_name}: {log_level}, {out_str}")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_malloc(ql: Qiling, hook_data):
    malloc(ql, hook_data)

def qsee_realloc(ql :Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
            {"oldptr": POINTER, "new_size": INT}
        )
    oldptr = p["oldptr"]
    new_size = p["new_size"]
    ql.log.info(f"qsee_realloc {hex(oldptr)} -> {hex(new_size)}")
    if oldptr == 0:
        malloc_core(ql, new_size, hook_data, False)
        return
    else:
        if oldptr not in hook_data.emu.HEAP["allocated"]:
            ql.log.critical(f"corrupted free qsee_realloc at: {hex(oldptr)}, {hook_data.emu.HEAP}")
            crash(ql, hook_data.func_name)
            return
    size = hook_data.emu.HEAP["allocated"][oldptr]
    hook_data.emu.update_shm(oldptr, size)
    try:
        olddata = ql.mem.read(oldptr, size)
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return
    free_core(ql, oldptr, hook_data, True)
    newptr = malloc_core(ql, new_size, hook_data, True)
    ql.mem.write(newptr, bytes(olddata[:min(size, new_size)]))
    ql.os.fcall.cc.setReturnValue(newptr)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_free(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
            {"ptr": POINTER}
        )
    free_core(ql, p["ptr"], hook_data, False)

def sm2_encrypt(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def calcsm3(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def sm4_crypt(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr