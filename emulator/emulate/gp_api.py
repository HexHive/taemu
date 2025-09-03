from enum import Enum
import time as pytime
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp.utils.printf import *
from .common import CRASH_PC, NOTIMPL_PC, crash
import unicorn

from Crypto.Random import get_random_bytes

from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE

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
        session_id_mem = ql.mem.map_anywhere(
            0x1000, minaddr=0x13000, info="session_id"
        )
        ql.mem.write(session_id_mem, session_id)
        ql.arch.regs.r0 = session_id_mem
    ql.arch.regs.r1 = command_id
    ql.arch.regs.r2 = parameters_type
    # setup TEE_Params
    params_mem = ql.mem.map_anywhere(
        0x1000, minaddr=0x130000, info="TEE_Params"
    )
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
    ql.log.critical(f"{hook_data.func_name} called, not implemented! lr: {hex(ql.arch.regs.lr)}")
    if hook_data.emu.crash_on_not_implemented:
        ql.arch.regs.arch_pc = NOTIMPL_PC
    else:
        ql.emu_stop()

def stack_chk_fail(ql: Qiling, hook_data):
    ql.log.critical(f"stack_chk_fail ***stack smashing detected***")
    crash(ql, hook_data.func_name)

def malloc(ql:Qiling, hook_data):
    TEE_Malloc(ql, hook_data)

def calloc(ql:Qiling, hook_data):
    calloc_core(ql, hook_data)

def TEE_Malloc(ql: Qiling, hook_data):
    malloc_core(ql, hook_data, False)    

def TEE_Free(ql: Qiling, hook_data):
    free_core(ql, hook_data, False)

def free(ql: Qiling, hook_data):
    free_core(ql, hook_data, False)

def memcmp(ql: Qiling, hook_data):
    TEE_MemCompare(ql, hook_data)

def TEE_GetREETime(ql: Qiling, hook_data):
    time_data = ql.os.resolve_fcall_params({"time": POINTER})["time"]
    try:
        ql.mem.write(time_data, int(pytime.time()).to_bytes(4, "little"))
        ql.mem.write(time_data+4, (0).to_bytes(4, "little"))
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_GetSystemTime(ql: Qiling, hook_data):
    TEE_GetREETime(ql, hook_data)

def TEE_LogPrintf(ql: Qiling, hook_data):
    try:
        format_param = ql.os.resolve_fcall_params({"format": STRING})["format"]
        final_params = {"format": STRING}
        params = parse_fmt_str(ql, format_param, final_params, hook_data.func_name)
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        format_param = format_param.replace("%p", "0x%x")
        format_param = format_param.replace("%llu", "%u")
        format_param = format_param.replace("%zu", "%u")
        out_str = format_param % tuple(string_params)
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

def TEE_LogvPrintf(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params({"log_level": INT, "format": STRING})
        log_level = p["log_level"]
        format_param = p["format"]
        final_params = {"log_level": INT, "format": STRING}
        params = parse_fmt_str(ql, format_param, final_params, hook_data.func_name)
        string_params = [params[f"{i}"] for i in range(0, len(params) - 1)]
        out_str = format_param % tuple(string_params)
        ql.log.info(f"{hook_data.func_name}: {log_level}, {out_str}")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def log_msg(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params(
            {"log_level": INT, "log_level_2": INT, "format": STRING}
        )
        log_level = p["log_level"]
        log_level_2 = p["log_level_2"]
        format_param = p["format"]
        final_params = {"log_level": INT, "log_level_2": INT, "format": STRING}
        final_params = parse_fmt_str(ql, format_param, final_params, hook_data.func_name)
        params = ql.os.resolve_fcall_params(final_params)
        del params["format"]
        string_params = [params[f"{i}"] for i in range(0, len(params) - 2)]
        format_param = format_param.replace("%p", "0x%x")
        format_param = format_param.replace("%llu", "%u")
        out_str = format_param % tuple(string_params)
        ql.log.info(f"log_msg: {log_level}, {log_level_2},{out_str}")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def snprintf(ql: Qiling, hook_data):
    try:
        params_initial = ql.os.resolve_fcall_params(
            {"s": POINTER, "n": INT, "format": STRING, "arg": POINTER}
        )
        format_param = params_initial["format"]
        n = params_initial["n"]
        s = params_initial["s"]
        arg = params_initial["arg"]
        params = parse_fmt_str(
            ql, format_param, {"s": INT, "n": INT, "format": STRING}, 
            hook_data.func_name, arg=arg
        )
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        out_str = format_param % tuple(string_params)
        full_len = len(out_str)
        out_str = out_str[: n - 1]
        out_str = out_str.encode("latin-1") + b"\x00"
        ql.log.info(f'{hook_data.func_name}: len: {hex(n)} "{out_str}" written to {hex(s)}, lr: {hex(ql.arch.regs.lr)}')
        if not asan.is_access_valid(ql, hook_data.emu.HEAP, s, len(out_str), hook_data.func_name, is_write=True):
            return
        ql.mem.write(s, out_str)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(full_len)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def sprintf(ql: Qiling, hook_data):
    params_initial = ql.os.resolve_fcall_params(
        {"s": POINTER, "format": STRING, "arg": POINTER}
    )
    format_param = params_initial["format"]
    s = params_initial["s"]
    arg = params_initial["arg"]
    try:
        params = parse_fmt_str(
            ql, format_param, {"s": INT, "format": STRING}, 
            hook_data.func_name, arg=arg
        )
        string_params = [params[f"{i}"] for i in range(0, len(params))]
        out_str = format_param % tuple(string_params)
        full_len = len(out_str)
        out_str = out_str.encode('latin-1') + b"\x00"
        ql.log.info(f'{hook_data.func_name}: "{out_str}" written to {hex(s)}')
        if not asan.is_access_valid(ql, hook_data.emu.HEAP, s, len(out_str), hook_data.func_name, is_write=True):
            return
        ql.mem.write(s, out_str)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(full_len)
    ql.arch.regs.arch_pc = ql.arch.regs.lr 

def vsnprintf(ql: Qiling, hook_data):
    snprintf(ql, hook_data)

def strlen(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    hook_data.emu.update_shm(ptr)
    try:
        string = read_c_str(ql, ptr)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    out = len(string)
    ql.log.info(f'strlen {hex(ptr)}: {out}')#, "{string}"=> {hex(out)}')
    ql.os.fcall.cc.setReturnValue(out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def strcpy(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"dst": POINTER, "src": POINTER})
    dst = params['dst']
    src = params['src']
    ql.log.info(f'{hook_data.func_name} {hex(src)}->{hex(dst)}')
    hook_data.emu.update_shm(src)
    try:
        s = read_c_str(ql, src)
        if not asan.is_access_valid(ql, hook_data.emu.HEAP, dst, len(s)+1, hook_data.func_name, is_write=True):
            return
        ql.mem.write(dst, s + b"\x00")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name) 
        return
    hook_data.emu.writeback_shm(dst)
    ql.os.fcall.cc.setReturnValue(dst)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def strncpy(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"dst": POINTER, "src": POINTER, 'num': POINTER})
    dst = params['dst']
    src = params['src']
    num = params['num']
    ql.log.info(f'{hook_data.func_name} {hex(src)}->{hex(dst)} ({num})')
    hook_data.emu.update_shm(src)
    try:
        s = read_c_str(ql, src)
        if len(s) >= num:
            if not asan.is_access_valid(ql, hook_data.emu.HEAP, dst, num, hook_data.func_name, is_write=True):
                return 
            ql.mem.write(dst, s[:num])
        else:
            if not asan.is_access_valid(ql, hook_data.emu.HEAP, dst, len(s)+1, hook_data.func_name, is_write=True):
                return
            ql.mem.write(dst, s+b"\x00")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name) 
        return
    hook_data.emu.writeback_shm(dst)
    ql.os.fcall.cc.setReturnValue(dst)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_MemMove(ql: Qiling, hook_data):
    memmove(ql, hook_data)

def memmove(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"dest": POINTER, "src": POINTER, "size": POINTER})
    ql.log.info(
        f'{hook_data.func_name} {params["size"]:#0x} from {hex(params["src"])} to {hex(params["dest"])}'
    )
    if not asan.is_access_valid(ql, hook_data.emu.HEAP, params["dest"], params["size"], hook_data.func_name, is_write=True):
        return
    if not asan.is_access_valid(ql, hook_data.emu.HEAP, params["src"], params["size"], hook_data.func_name, is_write=False):
        return
    hook_data.emu.update_shm(params["src"])
    try:
        data = ql.mem.read(params["src"], params["size"])
        ql.mem.write(params["dest"], bytes(data))
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name)
        return 
    hook_data.emu.writeback_shm(params["dest"])
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
    params = ql.os.resolve_fcall_params({"dest": POINTER, "src": POINTER, "size": POINTER})
    buffer_1 = params["dest"]
    buffer_2 = params["src"]
    size = params["size"]
    if not asan.is_access_valid(ql, hook_data.emu.HEAP, buffer_1, size, 
                                hook_data.func_name, is_write=False):
        return
    if not asan.is_access_valid(ql, hook_data.emu.HEAP, buffer_2, size, 
                                hook_data.func_name, is_write=False):
        return
    ret = 0
    hook_data.emu.update_shm(buffer_1)
    hook_data.emu.update_shm(buffer_2)
    try:
        content_1 = ql.mem.read(buffer_1, size)
        content_2 = ql.mem.read(buffer_2, size)
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name) 
        return 
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

    hook_data.emu.update_shm(str1)
    hook_data.emu.update_shm(str2)
    try:
        content_1 = read_c_str(ql, str1) 
        content_2 = read_c_str(ql, str2)
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, hook_data.func_name) 
        return

    if not asan.is_access_valid(ql, hook_data.emu.HEAP, str1, len(content_1), 
                                hook_data.func_name, is_write=False):
        return
    if not asan.is_access_valid(ql, hook_data.emu.HEAP, str2, len(content_2), 
                                hook_data.func_name, is_write=False):
        return
    ret = 0
    
    ql.log.info(f"{hook_data.func_name} compare {hex(str1)} with {hex(str2)}")
    for i in range(0, len(content_1)):
        if content_1[i] > content_2[i]:
            ret = 1
            break
        elif content_1[i] < content_2[i]:
            ret = -1
            break

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_GenerateRandom(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"randomBuffer": POINTER, "randomBufferLen": INT}
    )
    r = get_random_bytes(params["randomBufferLen"])
    try:
        ql.mem.write(params["randomBuffer"], r)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name) 
        return
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
        if buffer >= m[0] and buffer+size <= m[1]:
            found_mapping = m
            break
    if found_mapping is None:
        ql.os.fcall.cc.setReturnValue(TEE_ERROR_ACCESS_DENIED)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    if not(flags & TEE_MEMORY_ACCESS_ANY_OWNER):
        if "shared" in m[3]:
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
    param_ci = p['caller_info']
    # write tee_secure_info
    ql.mem.write_ptr(param_ci, 1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

