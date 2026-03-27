from enum import Enum
import functools
import os
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER

from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp_api import TEE_LogPrintf, malloc
from .common import crash, crash_notimpl
from .gp.utils.printf import parse_fmt_str, fixup_format, read_c_str




class SetupTeardownAction(Enum):
    SETUP = 0
    TEARDOWN = 1


class QseeCmdIdent(Enum):
    GPAppLibHandle = 0
    Cmd1 = 1
    CAppOpenSession = 2
    Cmd3 = 3
    Cmd4 = 4 # Something with tpidrro_el0



def _wrap_fcall_with_debug_log(func):
    @functools.wraps(func)
    def wrapper(ql: Qiling, hook_data):
        ql.log.info("Called func: %s", hook_data.func_name)
        ql.log.info("Ret ptr: %#x", ql.arch.regs.lr)
        val = func(ql, hook_data)
        ql.log.info("Returned value: %s", val)
    return wrapper

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

def cmnlib_init(ql: Qiling, hook_data):
    ql.log.info("cmnlib_init, back to %#x", ql.arch.regs.lr)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def acquire_sta_object(ql: Qiling, hook_data):
    ql.log.info("acquire_sta_object, back to %#x", ql.arch.regs.lr)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def GPAppLib_init(ql: Qiling, hook_data):
    ql.log.info("GPAppLib_init, back to %#x", ql.arch.regs.lr)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def GPAppLib_appInit(ql: Qiling, hook_data):
    ql.log.info("GPAppLib_appInit, back to %#x", ql.arch.regs.lr)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_prng_getdata(ql: Qiling, hook_data):
    args = ql.os.resolve_fcall_params({
        "data": POINTER,
        "size": INT,
    })

    data = args['data']
    size = args['size']
    ql.mem.write(data, os.urandom(size))

    ql.log.info("qsee_prng_getdata args: %s", args)
    ql.os.fcall.cc.setReturnValue(args['size'])
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_prng_seed(ql: Qiling, hook_data):
    ql.log.info("qsee_prng_seed, back to %#x", ql.arch.regs.lr)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_prng_stir(ql: Qiling, hook_data):
    ql.log.info("qsee_prng_stir, back to %#x", ql.arch.regs.lr)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_printf(ql: Qiling, hook_data):
    TEE_LogPrintf(ql, hook_data)
