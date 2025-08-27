from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp.utils.printf import *

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


def default_func(ql: Qiling, func_name):
    ql.log.info(f"{func_name} called, not implemented!")
    ql.emu_stop()

def stack_chk_fail(ql: Qiling, func_name):
    ql.log.critical(f"stack_chk_fail ***stack smashing detected***")
    ql.arch.regs.arch_pc = 0xdeadbeef

def malloc(ql:Qiling, func_name, called_from_custom_lib):
    TEE_Malloc(ql, func_name)

def calloc(ql:Qiling, func_name):
    calloc_core(ql, func_name)

def TEE_Malloc(ql: Qiling, func_name):
    malloc_core(ql, func_name, False)    

def TEE_Free(ql: Qiling, func_name):
    free_core(ql, func_name, False)

def free(ql: Qiling, func_name):
    free_core(ql, func_name, False)

def memcmp(ql: Qiling, func_name):
    TEE_MemCompare(ql, func_name)


def TEE_LogPrintf(ql: Qiling, func_name):
    format_param = ql.os.resolve_fcall_params({"format": STRING})["format"]
    final_params = {"format": STRING}
    params = parse_fmt_str(ql, format_param, final_params, func_name)
    string_params = [params[f"{i}"] for i in range(0, len(params))]
    format_param = format_param.replace("%p", "0x%x")
    format_param = format_param.replace("%llu", "%u")
    format_param = format_param.replace("%zu", "%u")
    out_str = format_param % tuple(string_params)
    ql.log.info(f"{func_name}: {out_str}")
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def fprintf(ql: Qiling, func_name):
    TEE_LogvPrintf(ql, func_name)

def vfprintf(ql: Qiling, func_name):
    TEE_LogvPrintf(ql, func_name)

def puts(ql: Qiling, func_name):
    TEE_LogPrintf(ql, func_name)

def printf(ql: Qiling, func_name):
    TEE_LogPrintf(ql, func_name)

def TEE_LogvPrintf(ql: Qiling, func_name):
    p = ql.os.resolve_fcall_params({"log_level": INT, "format": STRING})
    log_level = p["log_level"]
    format_param = p["format"]
    final_params = {"log_level": INT, "format": STRING}
    params = parse_fmt_str(ql, format_param, final_params, func_name)
    string_params = [params[f"{i}"] for i in range(0, len(params) - 1)]
    out_str = format_param % tuple(string_params)
    ql.log.info(f"{func_name}: {log_level}, {out_str}")
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def log_msg(ql: Qiling, func_name):
    p = ql.os.resolve_fcall_params(
        {"log_level": INT, "log_level_2": INT, "format": STRING}
    )
    log_level = p["log_level"]
    log_level_2 = p["log_level_2"]
    format_param = p["format"]
    final_params = {"log_level": INT, "log_level_2": INT, "format": STRING}
    final_params = parse_fmt_str(format_param, final_params)
    params = ql.os.resolve_fcall_params(final_params)
    del params["format"]
    string_params = [params[f"{i}"] for i in range(0, len(params) - 2)]
    format_param = format_param.replace("%p", "0x%x")
    format_param = format_param.replace("%llu", "%u")
    out_str = format_param % tuple(string_params)
    ql.log.info(f"log_msg: {log_level}, {log_level_2},{out_str}")
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def snprintf(ql: Qiling, func_name):
    params_initial = ql.os.resolve_fcall_params(
        {"s": POINTER, "n": INT, "format": STRING, "arg": POINTER}
    )
    format_param = params_initial["format"]
    n = params_initial["n"]
    s = params_initial["s"]
    arg = params_initial["arg"]
    params = parse_fmt_str(
        ql, format_param, {"s": INT, "n": INT, "format": STRING}, 
        func_name, arg=arg
    )
    string_params = [params[f"{i}"] for i in range(0, len(params))]
    out_str = format_param % tuple(string_params)
    full_len = len(out_str)
    out_str = out_str[: n - 1]
    out_str = out_str.encode() + b"\x00"
    ql.log.info(f'{func_name}: len: {hex(n)} "{out_str}" written to {hex(s)}')
    ql.mem.write(s, out_str)
    ql.os.fcall.cc.setReturnValue(full_len)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def vsnprintf(ql: Qiling, func_name):
    snprintf(ql, func_name)

def strlen(ql: Qiling, func_name):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    ql.log.info(f'strlen {hex(ptr)}')#, "{string}"=> {hex(out)}')
    string = read_c_str(ql, ptr)
    out = len(string)
    ql.os.fcall.cc.setReturnValue(out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def strcpy(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dst": POINTER, "src": POINTER})
    dst = params['dst']
    src = params['src']
    ql.log.info(f'{func_name} {hex(src)}->{hex(dst)}')
    s = read_c_str(ql, src)
    ql.mem.write(dst, s + b"\x00")
    ql.os.fcall.cc.setReturnValue(dst)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def strncpy(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dst": POINTER, "src": POINTER, 'num': POINTER})
    dst = params['dst']
    src = params['src']
    num = params['num']
    ql.log.info(f'{func_name} {hex(src)}->{hex(dst)} ({num})')
    s = read_c_str(ql, src)
    if len(s) >= num:
        ql.mem.write(dst, s[:num])
    else:
        ql.mem.write(dst, s+b"\x00")
    ql.os.fcall.cc.setReturnValue(dst)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEE_MemMove(ql: Qiling, func_name):
    memmove(ql, func_name)

def memmove(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dest": POINTER, "src": POINTER, "size": POINTER})
    ql.log.info(
        f'{func_name} {params["size"]:#0x} from {hex(params["src"])} to {hex(params["dest"])}'
    )
    data = ql.mem.read(params["src"], params["size"])
    ql.mem.write(params["dest"], bytes(data))
    ql.os.fcall.cc.setReturnValue(params["dest"])
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def memcpy(ql: Qiling, func_name):
    memmove(ql, func_name)


def TEE_MemFill(ql: Qiling, func_name):
    memfill(ql, func_name)


def memfill(ql: Qiling, func_name):
    memset_core(ql, func_name, False)


def memset(ql: Qiling, func_name):
    memfill(ql, func_name)


def TEE_MemCompare(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params({"dest": POINTER, "src": POINTER, "size": POINTER})
    buffer_1 = params["dest"]
    buffer_2 = params["src"]
    size = params["size"]

    ret = 0
    content_1 = ql.mem.read(buffer_1, size)
    content_2 = ql.mem.read(buffer_2, size)
    ql.log.info(f"{func_name} compare {content_1} with {content_2}")
    for i in range(size):
        if content_1[i] > content_2[i]:
            ret = 1
            break
        elif content_1[i] < content_2[i]:
            ret = -1
            break

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_GenerateRandom(ql: Qiling, func_name):
    params = ql.os.resolve_fcall_params(
        {"randomBuffer": POINTER, "randomBufferLen": INT}
    )
    r = get_random_bytes(params["randomBufferLen"])
    ql.mem.write(params["randomBuffer"], r)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_CheckMemoryAccessRights(ql: Qiling, func_name):
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


def TEE_RpmbOpenSession(ql: Qiling, func_name):
    rpmb.TEE_RpmbOpenSession(ql, func_name)


def TEE_RpmbCloseSession(ql: Qiling, func_name):
    rpmb.TEE_RpmbCloseSession(ql, func_name)


def TEE_RpmbReadData(ql: Qiling, func_name):
    rpmb.TEE_RpmbReadData(ql, func_name)


def TEE_RpmbWriteData(ql: Qiling, func_name):
    rpmb.TEE_RpmbWriteData(ql, func_name)

def TEE_GetCallerInfo(ql: Qiling, func_name):
    p = ql.os.resolve_fcall_params({"caller_info": POINTER})
    param_ci = p['caller_info']
    # write tee_secure_info
    ql.mem.write_ptr(param_ci, 1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

