from enum import Enum
import os
import time as pytime
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from . import asan
from .gp.utils.printf import *
from .gp.utils.const import *
from .common import CRASH_PC, NOTIMPL_PC, crash, crash_notimpl, finalize_fuzzing
from .fuzz_record import Status
from . import cmplog
from . import telemetry
import unicorn

from .determinism import get_random_bytes, now as _det_now

from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .emulator_no_loader import HookData

def GP_params_setup(
    ql: Qiling, command_id, parameters_type, tee_params, session_id=None
):
    """
    r0: session_id
    r1: command_id
    r2: parameters_type
    r3: TEE_Param parameters (pointer to a TEE_Params structure)
    """
    if session_id is not None:
        session_id_mem = ql.mem.map_anywhere(0x1000, minaddr=0x13000, info="session_id")
        ql.mem.write(session_id_mem, session_id)
        ql.arch.regs.r0 = session_id_mem
    ql.arch.regs.r1 = command_id
    ql.arch.regs.r2 = parameters_type
    # setup TEE_Params
    params_mem = ql.mem.map_anywhere(0x1000, minaddr=0x130000, info="TEE_Params")
    ql.arch.regs.r3 = params_mem
    for i, tee_param in enumerate(tee_params):
        if isinstance(tee_param, TEE_Param_Memref):
            memref_memory = ql.mem.map_anywhere(
                tee_param.len, minaddr=0x130000, info=f"memref_param_{i}"
            )
            tee_param.ptr = memref_memory
            ql.mem.write(memref_memory, tee_param.data)
            ql.mem.write_ptr(params_mem, tee_param.ptr)
            params_mem += 4
            ql.mem.write_ptr(params_mem, tee_param.len)
            params_mem += 4


def default_func(ql: Qiling, hook_data):
    telemetry.record(hook_data.func_name)  # triage signal: this symbol is a stub
    ql.log.critical(f"{hook_data.func_name} called, not implemented! lr: {hex(ql.arch.regs.lr)}")
    if hook_data.emu.crash_on_not_implemented:
        ql.arch.regs.arch_pc = NOTIMPL_PC
    else:
        ql.emu_stop()
        if ql.emu.status in (Status.REPLAYING, Status.FUZZING):
            finalize_fuzzing(ql, user_data="early_exit")


def stack_chk_fail(ql: Qiling, hook_data):
    ql.log.critical(f"stack_chk_fail ***stack smashing detected***")
    crash(ql, hook_data.func_name)

def getenv(ql: Qiling, hook_data):
    param = ql.os.resolve_fcall_params({"nmemb": STRING})
    data = param["nmemb"]
    ql.log.info(f'getenv: {data}')
    if data == "RUST_LIB_BACKTRACE":
        env_mem = ql.mem.map_anywhere(0x1000, minaddr=0x13000, info="getenv") 
        ql.mem.write(env_mem, b"0\x00")
        ql.os.fcall.cc.setReturnValue(env_mem)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    else:
       breakpoint()
       ql.arch.regs.arch_pc = NOTIMPL_PC 

def malloc(ql: Qiling, hook_data):
    TEE_Malloc(ql, hook_data)

def realloc(ql: Qiling, hook_data):
    TEE_Realloc(ql, hook_data)

def TEE_Realloc(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
            {"oldptr": POINTER, "new_size": INT}
        )
    oldptr = p["oldptr"]
    new_size = p["new_size"]
    ql.log.info(f"realloc {hex(oldptr)} -> {hex(new_size)}")
    if oldptr == 0:
        malloc_core(ql, new_size, hook_data, False)
        return
    else:
        if oldptr not in hook_data.emu.HEAP["allocated"]:
            ql.log.critical(f"corrupted free realloc at: {hex(oldptr)}, {hook_data.emu.HEAP}")
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

def calloc(ql: Qiling, hook_data):
    param = ql.os.resolve_fcall_params({"nmemb": INT, "size": INT})
    calloc_core(ql, param["nmemb"] , param["size"], hook_data, False)


def TEE_Malloc(ql: Qiling, hook_data):
    size = ql.os.resolve_fcall_params({"size": INT})["size"]
    malloc_core(ql, size, hook_data, False)

def memalign(ql: Qiling, hook_data: 'HookData'):
    params = ql.os.resolve_fcall_params({"alignment": INT, "size": INT})
    size = params["size"]
    alignment = params["alignment"]
    func_name = hook_data.func_name

    real_size = asan.memory_alignment_round_up(
        size + alignment + 2 * asan.ASAN_REDZONE_SIZE, 0x1000
    )

    out = ql.mem.map_anywhere(real_size, minaddr=HEAP_MEM, perms=3, info="malloc_chunk")
    candidate = out + asan.ASAN_REDZONE_SIZE
    aligned = (candidate + (alignment - 1)) & ~(alignment - 1)
    ret2user_out = aligned 
    ql.log.info(f"{func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    hook_data.emu.HEAP["allocated"][ret2user_out] = size
    if ret2user_out in hook_data.emu.HEAP["freed"]:
        del hook_data.emu.HEAP["freed"][ret2user_out]

    ql.log.info(f"redzone hook {hex(out)}")
    hook_data.emu.asan.hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE)
    hook_data.emu.HEAP["redzones"][out] = asan.ASAN_REDZONE_SIZE
    ql.log.info(f"redzone hook {hex(ret2user_out + size)}")
    hook_data.emu.asan.hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size
    )
    hook_data.emu.HEAP["redzones"][ret2user_out + size] = (
        real_size - asan.ASAN_REDZONE_SIZE - size
    )

    ql.os.fcall.cc.setReturnValue(ret2user_out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
    return 
    

def TEE_Free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": INT})["ptr"]
    free_core(ql, ptr, hook_data, False)


def free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": INT})["ptr"]
    free_core(ql, ptr, hook_data, False)

def TEE_GetCancellationFlag(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def memcmp(ql: Qiling, hook_data):
    TEE_MemCompare(ql, hook_data)


def TEE_GetREETime(ql: Qiling, hook_data):
    time_data = ql.os.resolve_fcall_params({"time": POINTER})["time"]
    try:
        ql.mem.write(time_data, _det_now().to_bytes(4, "little"))
        ql.mem.write(time_data + 4, (0).to_bytes(4, "little"))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(time_data, 8)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_GetSystemTime(ql: Qiling, hook_data):
    TEE_GetREETime(ql, hook_data)


# def TEE_GetTAPersistentTime(ql: Qiling, hook_data):
# TEE_GetREETime(ql, hook_data)

# def TEE_SetTAPersistentTime(ql: Qiling, hook_data):
# ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
# ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_Wait(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_LogPrintf(ql: Qiling, hook_data):
    try:
        format_param_ptr = ql.os.resolve_fcall_params({"format": POINTER})["format"]
        hook_data.emu.update_shm(format_param_ptr)
        format_param = ql.mem.string(format_param_ptr)
        ql.log.debug("format_param: '%s'", format_param)
        ql.log.debug("Back to %#x", ql.arch.regs.lr)
        final_params = {"format": STRING}
        params = parse_fmt_str(ql, format_param, final_params, hook_data.func_name)
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        format_param = format_param.replace("%p", "0x%x")
        format_param = format_param.replace("%llu", "%u")
        format_param = format_param.replace("%zu", "%u")
        try:
            out_str = format_param % tuple(string_params)
        except (ValueError, TypeError):
            ql.log.error(f"format string not supported: {format_param}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"format string not supported: {format_param}")
                return
            # don't reference an unset out_str; return SUCCESS so the TA's own
            # logic (incl. any OOB it is about to do) keeps running.
            ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
        ql.log.info(f"{hook_data.func_name}: {out_str}")
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def fprintf(ql: Qiling, hook_data):
    TEE_LogvPrintf(ql, hook_data)


def vfprintf(ql: Qiling, hook_data):
    TEE_LogvPrintf(ql, hook_data)


def puts(ql: Qiling, hook_data):
    try:
        out = ql.os.resolve_fcall_params({"format": STRING})["format"]
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.log.info(f"{hook_data.func_name}: {out}")
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def printf(ql: Qiling, hook_data):
    TEE_LogPrintf(ql, hook_data)


def strstr(ql, hook_data):
    params = ql.os.resolve_fcall_params({"str1": POINTER, "str2": POINTER})
    str1 = params["str1"]
    str2 = params["str2"]
    hook_data.emu.update_shm(str1)
    hook_data.emu.update_shm(str2)
    s1 = read_c_str(ql, str1)
    s2 = read_c_str(ql, str2)
    ql.log.info(f"strstr {s1}, {s2}")
    try:
        ql.os.fcall.cc.setReturnValue(s1.index(s2))
    except:
        ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def strncat(ql, hook_data):
    params = ql.os.resolve_fcall_params({"str1": POINTER, "str2": POINTER, "n": INT})
    str1 = params["str1"]
    str2 = params["str2"]
    n = params["n"]
    hook_data.emu.update_shm(str1, n)
    hook_data.emu.update_shm(str2, n)
    s1 = read_c_str(ql, str1)
    s2 = read_c_str(ql, str2)
    ql.log.info(f"strncat: {hex(str1)}->{hex(str2)} {n}")
    dest = str1 + len(s1)
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP,
        dest,
        min(n, len(s2)),
        hook_data.func_name,
        is_write=True,
    ):
        return
    ql.mem.write(dest, s1[:n])
    hook_data.emu.writeback_shm(dest, n)
    ql.os.fcall.cc.setReturnValue(dest)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_LogvPrintf(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params({"log_level": INT, "format": POINTER})
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


def TEE_GetPropertyAsIdentity(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params(
            {"propsetOrEnumerator": POINTER, "name": STRING, "value": POINTER}
        )
        propset = p["propsetOrEnumerator"]
        name = p["name"]
        value = p["value"]
        if propset == TEE_PROPSET_CURRENT_CLIENT and name == "gpd.client.identity":
            # Default is TEE_LOGIN_PUBLIC(0). TAEMU_FORCE_LOGIN lets a harness drive a
            # specific client login method (e.g. 4=TEE_LOGIN_USER for KEYMST's REE path)
            # so a probe can reach a post-login paramTypes pin instead of stopping at the
            # TA's login gate. No effect when the env var is unset.
            _login = int(os.environ.get("TAEMU_FORCE_LOGIN", str(TEE_LOGIN_PUBLIC)), 0)
            ql.mem.write(value, (_login & 0xffffffff).to_bytes(4, "little"))
            hook_data.emu.writeback_shm(value, 4)
            ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
        else:
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"unknown property.. {name} {hex(propset)}")
                return
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return


def log_msg(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params(
            {"log_level": INT, "log_level_2": INT, "format": POINTER}
        )
        log_level = p["log_level"]
        log_level_2 = p["log_level_2"]
        format_param_ptr = p["format"]
        hook_data.emu.update_shm(format_param_ptr)
        format_param = ql.mem.string(format_param_ptr)
        final_params = {"log_level": INT, "log_level_2": INT, "format": STRING}
        final_params = parse_fmt_str(
            ql, format_param, final_params, hook_data.func_name
        )
        params = ql.os.resolve_fcall_params(final_params)
        del params["format"]
        string_params = [params[f"{i}"] for i in range(0, len(params) - 2)]
        format_param = fixup_format(format_param)
        try:
            out_str = format_param % tuple(string_params)
        except TypeError:
            ql.log.error(f"format string not supported: {format_param}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"format string not supported: {format_param}")
                return
        ql.log.info(f"log_msg: {log_level}, {log_level_2},{out_str}")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def snprintf(ql: Qiling, hook_data):
    try:
        params_initial = ql.os.resolve_fcall_params(
            {"s": POINTER, "n": INT, "format": POINTER, "arg": POINTER}
        )
        format_param_ptr = params_initial["format"]
        hook_data.emu.update_shm(format_param_ptr)
        format_param = ql.mem.string(format_param_ptr)
        n = params_initial["n"]
        s = params_initial["s"]
        arg = params_initial["arg"]
        params = parse_fmt_str(
            ql,
            format_param,
            {"s": INT, "n": INT, "format": STRING},
            hook_data.func_name,
            arg=arg,
        )
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        format_param = fixup_format(format_param)
        try:
            out_str = format_param % tuple(string_params)
        except TypeError:
            ql.log.error(f"format string not supported: {format_param}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"format string not supported: {format_param}")
                return
        full_len = len(out_str)
        out_str = out_str[: n - 1]
        out_str = out_str.encode("latin-1") + b"\x00"
        ql.log.info(
            f'{hook_data.func_name}: len: {hex(n)} "{out_str}" written to {hex(s)}, lr: {hex(ql.arch.regs.lr)}'
        )
        if not hook_data.emu.asan.is_access_valid(
            hook_data.emu.HEAP, s, len(out_str), hook_data.func_name, is_write=True
        ):
            return
        ql.mem.write(s, out_str)
        hook_data.emu.writeback_shm(s, len(out_str))
    except unicorn.unicorn_py3.unicorn.UcError as e:
        raise e
        crash(ql, hook_data.func_name)
        return

    ql.os.fcall.cc.setReturnValue(full_len)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def sprintf(ql: Qiling, hook_data):
    params_initial = ql.os.resolve_fcall_params(
        {"s": POINTER, "format": POINTER, "arg": POINTER}
    )
    format_param_ptr = params_initial["format"]
    hook_data.emu.update_shm(format_param_ptr)
    format_param = ql.mem.string(format_param_ptr)
    s = params_initial["s"]
    arg = params_initial["arg"]
    try:
        params = parse_fmt_str(
            ql, format_param, {"s": INT, "format": STRING}, hook_data.func_name, arg=arg
        )
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        format_param = fixup_format(format_param)
        try:
            out_str = format_param % tuple(string_params)
        except TypeError:
            ql.log.error(f"format string not supported: {format_param}")
            if hook_data.emu.crash_on_not_implemented:
                crash_notimpl(ql, f"format string not supported: {format_param}")
                return
        full_len = len(out_str)
        out_str = out_str.encode("latin-1") + b"\x00"
        ql.log.info(f'{hook_data.func_name}: "{out_str}" written to {hex(s)}')
        if not hook_data.emu.asan.is_access_valid(
            hook_data.emu.HEAP, s, len(out_str), hook_data.func_name, is_write=True
        ):
            return
        ql.mem.write(s, out_str)
        hook_data.emu.writeback_shm(s, len(out_str))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(full_len)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def vsnprintf(ql: Qiling, hook_data):
    snprintf(ql, hook_data)


def vsprintf(ql: Qiling, hook_data):
    # vsprintf(s, format, va_list): we don't model va_list arg fetching (the
    # args live behind the va_list pointer, not in the normal vararg
    # registers), so write the format string best-effort and never crash the
    # emulator. Typically a log/debug line, so an unexpanded specifier is
    # harmless; the alternative (aliasing sprintf) KeyErrors on the va_list.
    try:
        p = ql.os.resolve_fcall_params({"s": POINTER, "format": STRING})
        out = p["format"].encode("latin-1", "replace") + b"\x00"
        if asan.is_access_valid(ql, hook_data.emu.HEAP, p["s"], len(out), hook_data.func_name, is_write=True):
            ql.mem.write(p["s"], out)
        ql.os.fcall.cc.setReturnValue(len(out) - 1)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    except Exception:
        ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def strlen(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    hook_data.emu.update_shm(ptr)
    try:
        string = read_c_str(ql, ptr)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    out = len(string)
    ql.log.info(f"strlen {hex(ptr)}: {out}")  # , "{string}"=> {hex(out)}')
    ql.os.fcall.cc.setReturnValue(out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def strnlen(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"ptr": POINTER, "len": POINTER})
    ptr = params["ptr"]
    length = params["len"]
    hook_data.emu.update_shm(ptr, length)
    try:
        string = read_c_str(ql, ptr)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    out = len(string)
    if out > length:
        out = length
    ql.log.info(f"strlen {hex(ptr)}: {out}")  # , "{string}"=> {hex(out)}')
    ql.os.fcall.cc.setReturnValue(out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def strcpy(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"dst": POINTER, "src": POINTER})
    dst = params["dst"]
    src = params["src"]
    ql.log.info(f"{hook_data.func_name} {hex(src)}->{hex(dst)}")
    hook_data.emu.update_shm(src)  # +1 for the null terminator
    try:
        s = read_c_str(ql, src)
        if not hook_data.emu.asan.is_access_valid(
            hook_data.emu.HEAP, dst, len(s) + 1, hook_data.func_name, is_write=True
        ):
            return
        ql.mem.write(dst, s + b"\x00")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(dst, len(s)+1)
    ql.os.fcall.cc.setReturnValue(dst)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def strncpy(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"dst": POINTER, "src": POINTER, "num": POINTER}
    )
    dst = params["dst"]
    src = params["src"]
    num = params["num"]
    ql.log.info(f"{hook_data.func_name} {hex(src)}->{hex(dst)} ({num})")
    hook_data.emu.update_shm(src, num)
    try:
        s = read_c_str(ql, src)
        if len(s) >= num:
            if not hook_data.emu.asan.is_access_valid(
                hook_data.emu.HEAP, dst, num, hook_data.func_name, is_write=True
            ):
                return
            ql.mem.write(dst, s[:num])
        else:
            if not hook_data.emu.asan.is_access_valid(
                hook_data.emu.HEAP,
                dst,
                len(s) + 1,
                hook_data.func_name,
                is_write=True,
            ):
                return
            ql.mem.write(dst, s + b"\x00")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(dst, min(len(s), num))
    ql.os.fcall.cc.setReturnValue(dst)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def strcat(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"dst": POINTER, "src": POINTER}
    )
    dst = params["dst"]
    src = params["src"]
    ql.log.info(f"strcat {hex(dst)} <- {hex(src)}")

    hook_data.emu.update_shm(src)
    hook_data.emu.update_shm(dst)
    try:
        dst_str = read_c_str(ql, dst)
        new_dest = dst + len(dst_str)
        src_str = read_c_str(ql, src)
        ql.mem.write(new_dest, src_str)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(dst)
    ql.os.fcall.cc.setReturnValue(dst)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def stpcpy(ql: Qiling, hook_data):
    # like strcpy but returns a pointer to the copied terminating NUL
    params = ql.os.resolve_fcall_params({"dst": POINTER, "src": POINTER})
    dst = params["dst"]
    src = params["src"]
    hook_data.emu.update_shm(src)
    try:
        s = read_c_str(ql, src)
        if not asan.is_access_valid(ql, hook_data.emu.HEAP, dst, len(s) + 1, hook_data.func_name, is_write=True):
            return
        ql.mem.write(dst, s + b"\x00")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(dst)
    ql.os.fcall.cc.setReturnValue(dst + len(s))
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def mempcpy(ql: Qiling, hook_data):
    # memcpy that returns dst+n (a pointer past the last written byte)
    params = ql.os.resolve_fcall_params({"dest": POINTER, "src": POINTER, "size": POINTER})
    if not asan.is_access_valid(ql, hook_data.emu.HEAP, params["dest"], params["size"], hook_data.func_name, is_write=True):
        return
    hook_data.emu.update_shm(params["src"])
    try:
        data = ql.mem.read(params["src"], params["size"])
        ql.mem.write(params["dest"], bytes(data))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(params["dest"])
    ql.os.fcall.cc.setReturnValue(params["dest"] + params["size"])
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_MemMove(ql: Qiling, hook_data):
    memmove(ql, hook_data)


def memmove(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"dest": POINTER, "src": POINTER, "size": POINTER}
    )
    ql.log.info(
        f'{hook_data.func_name} {params["size"]:#0x} from {hex(params["src"])} to {hex(params["dest"])}'
    )
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP,
        params["dest"],
        params["size"],
        hook_data.func_name,
        is_write=True,
    ):
        return
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP,
        params["src"],
        params["size"],
        hook_data.func_name,
        is_write=False,
    ):
        return
    hook_data.emu.update_shm(params["src"], params["size"])
    try:
        data = ql.mem.read(params["src"], params["size"])
        ql.mem.write(params["dest"], bytes(data))
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(params["dest"], params["size"])
    ql.os.fcall.cc.setReturnValue(params["dest"])
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def memcpy(ql: Qiling, hook_data):
    memmove(ql, hook_data)


def TEE_MemFill(ql: Qiling, hook_data):
    memfill(ql, hook_data)


def memfill(ql: Qiling, hook_data):
    memset_core(ql, hook_data, False)


def memset(ql: Qiling, hook_data):
    memfill(ql, hook_data)


def TEE_MemCompare(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"dest": POINTER, "src": POINTER, "size": POINTER}
    )
    buffer_1 = params["dest"]
    buffer_2 = params["src"]
    size = params["size"]
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP, buffer_1, size, hook_data.func_name, is_write=False
    ):
        return
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP, buffer_2, size, hook_data.func_name, is_write=False
    ):
        return
    ret = 0
    hook_data.emu.update_shm(buffer_1, size)
    hook_data.emu.update_shm(buffer_2, size)
    try:
        content_1 = ql.mem.read(buffer_1, size)
        content_2 = ql.mem.read(buffer_2, size)
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return
    cmplog.record(content_1, content_2)  # harvest compare operands for the AFL dict
    ql.log.info(f"{hook_data.func_name} compare {hex(buffer_1)} with {hex(buffer_2)}")
    for i in range(size):
        if content_1[i] > content_2[i]:
            ret = 1
            break
        elif content_1[i] < content_2[i]:
            ret = -1
            break

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def strcmp(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"str1": POINTER, "str2": POINTER})
    str1 = params["str1"]
    str2 = params["str2"]
    hook_data.emu.update_shm(str1)  # +1 for the null terminator
    hook_data.emu.update_shm(str2)

    try:
        content_1 = read_c_str(ql, str1)
        content_2 = read_c_str(ql, str2)
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP,
        str1,
        len(content_1),
        hook_data.func_name,
        is_write=False,
    ):
        return
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP,
        str2,
        len(content_2),
        hook_data.func_name,
        is_write=False,
    ):
        return
    ret = 0

    cmplog.record(content_1, content_2)  # harvest compare operands for the AFL dict
    ql.log.info(f"{hook_data.func_name} compare {hex(str1)} with {hex(str2)}")
    for i in range(0, min(len(content_1), len(content_2))):
        if content_1[i] > content_2[i]:
            ret = 1
            break
        elif content_1[i] < content_2[i]:
            ret = -1
            break

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def strncmp(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"str1": POINTER, "str2": POINTER, "size": POINTER}
    )
    str1 = params["str1"]
    str2 = params["str2"]
    size = params["size"]

    hook_data.emu.update_shm(str1, size)
    hook_data.emu.update_shm(str2, size)
    try:
        content_1 = read_c_str(ql, str1)
        content_2 = read_c_str(ql, str2)
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return

    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP,
        str1,
        len(content_1),
        hook_data.func_name,
        is_write=False,
    ):
        return
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP,
        str2,
        len(content_2),
        hook_data.func_name,
        is_write=False,
    ):
        return
    ret = 0

    cmplog.record(content_1, content_2)  # harvest compare operands for the AFL dict
    ql.log.info(f"{hook_data.func_name} compare {hex(str1)} with {hex(str2)}")
    for i in range(0, min(len(content_1), len(content_2))):
        if content_1[i] > content_2[i]:
            ret = 1
            break
        elif content_1[i] < content_2[i]:
            ret = -1
            break
        if i == size:
            break

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_GenerateRandom(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"randomBuffer": POINTER, "randomBufferLen": INT}
    )
    r = b"A" * params["randomBufferLen"]
    try:
        ql.mem.write(params["randomBuffer"], r)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    hook_data.emu.writeback_shm(params["randomBuffer"], params["randomBufferLen"])
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_CheckMemoryAccessRights(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"accessFlags": INT, "buffer": POINTER, "size": INT}
    )
    flags = params["accessFlags"]
    buffer = params["buffer"]
    size = params["size"]
    ql.log.info(f"TEE_CHeckMemoryAccessRights: .{params}")
    found_mapping = None
    for m in ql.mem.map_info:
        if buffer >= m[0] and buffer + size <= m[1]:
            found_mapping = m
            break
    if found_mapping is None:
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_ACCESS_DENIED)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    if not (flags & TEE_MEMORY_ACCESS_ANY_OWNER):
        if hook_data.emu.is_ree_addr(buffer, size) or "shared" in m[3]:
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_ACCESS_DENIED)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
    if flags & TEE_MEMORY_ACCESS_READ:
        if not (m[2] & UC_PROT_READ):
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_ACCESS_DENIED)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
    if flags & TEE_MEMORY_ACCESS_WRITE:
        if not (m[2] & UC_PROT_WRITE):
            ql.os.fcall.cc.setReturnValue(TEE_ERROR_ACCESS_DENIED)
            ql.arch.regs.arch_pc = ql.arch.regs.lr
            return
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_RpmbOpenSession(ql: Qiling, hook_data):
    rpmb.TEE_RpmbOpenSession(ql, hook_data)


def TEE_RpmbCloseSession(ql: Qiling, hook_data):
    rpmb.TEE_RpmbCloseSession(ql, hook_data)


def TEE_RpmbReadData(ql: Qiling, hook_data):
    rpmb.TEE_RpmbReadData(ql, hook_data)


def TEE_RpmbWriteData(ql: Qiling, hook_data):
    rpmb.TEE_RpmbWriteData(ql, hook_data)


def TEE_GetCallerInfo(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"caller_info": POINTER})
    param_ci = p["caller_info"]
    # write tee_secure_info
    ql.mem.write_ptr(param_ci, 1)
    hook_data.emu.writeback_shm(param_ci)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def __errno_location(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
    
def strtol(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"str": POINTER, "endptr": POINTER, "base": INT})
    strp = p["str"]
    while ql.mem.read(strp,1) == b" ": 
        strp += 1
    base = p["base"]
    nr = ""
    if base == 10:
        while True:
            c = ql.mem.read(strp,1)
            if c in [b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"]:
                nr = nr + c.decode() 
                strp += 1
            else:
                break
    elif base == 16:
        while True:
            c = ql.mem.read(strp,1)
            if c in [b"A", b"B", b"C", b"D", b"E", b"F", b"a", b"b", b"c", b"d", b"e", b"f", b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"]:
                nr = nr + c.decode() 
                strp += 1
            else:
                break
    a = int(nr, p["base"])
    ql.os.fcall.cc.setReturnValue(a)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
    
def __assert_fail(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"lvl": INT, "file": STRING, "line": INT, "func": STRING})
    ql.log.info(f'__assert_fail {p["file"]}:{p["line"]}->{p["func"]}') 
    ql.emu.stop()


def strchr(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"s": POINTER, "c": INT})
    s = params["s"]
    c = params["c"] & 0xFF
    hook_data.emu.update_shm(s)
    addr = s
    try:
        # cap the scan so a corrupted / unterminated string can't spin forever
        for _ in range(0x10000):
            b = ql.mem.read(addr, 1)[0]
            if b == c:
                ql.os.fcall.cc.setReturnValue(addr)
                ql.arch.regs.arch_pc = ql.arch.regs.lr
                return
            if b == 0:
                # strchr(s, '\0') returns a pointer to the terminating NUL
                ql.os.fcall.cc.setReturnValue(addr if c == 0 else 0)
                ql.arch.regs.arch_pc = ql.arch.regs.lr
                return
            addr += 1
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def _TEE_Panic(ql: Qiling, hook_data):
    code = ql.os.resolve_fcall_params({"code": INT})["code"]
    ql.log.critical(f"TEE_Panic(code={hex(code)}) — TA called panic, aborting")
    ql.emu_stop()


def TEE_Panic(ql: Qiling, hook_data):
    _TEE_Panic(ql, hook_data)
