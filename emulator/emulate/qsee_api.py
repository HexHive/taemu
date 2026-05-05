from collections import defaultdict
from dataclasses import dataclass
import datetime
from enum import Enum
import functools
import hashlib
import os
import random
import struct
from colorama import Fore
import pwn
from qiling import Qiling
from qiling.os.const import LONGLONG, STRING, INT, BYTE, POINTER

from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .gp_api import TEE_LogPrintf, malloc
from .common import crash, crash_notimpl
from .gp.utils.printf import parse_fmt_str, fixup_format, read_c_str
import time
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .emulator_no_loader import HookData

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

def qsee_is_sw_fuse_blown(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
            {"idk": INT, "out": POINTER}
        )
    ql.mem.write(p["out"], 4*b"\x00")
    _ret(ql, 0)

__current_log_mask = 0
def qsee_log_set_mask(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params(
        {"mask": BYTE}
    )
    __current_log_mask = p["mask"] & 0x1f
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_log_get_mask(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(__current_log_mask)
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
        # overengineered pretty printing
        l1 = len(out_str) - len(out_str.rstrip())
        out_str = out_str.rstrip() + Fore.RED + "\\n"*l1 + Fore.RESET
        if "\n" in out_str:
            for i, line in enumerate(out_str.split("\n")):
                ql.log.info("%s: [%s]/L%02d:  %s", hook_data.func_name, log_level, i, line)
        else:
            ql.log.info("%s: [%s]: %s", hook_data.func_name, log_level, out_str)
            
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
    _ret(ql, 0)

def calcsm3(ql: Qiling, hook_data):
    _ret(ql, 0)

def sm4_crypt(ql: Qiling, hook_data):
    _ret(ql, 0)

def cmnlib_init(ql: Qiling, hook_data):
    ql.log.info("cmnlib_init, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def cmnlib_release(ql: Qiling, hook_data):
    ql.log.info("cmnlib_release, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def acquire_sta_object(ql: Qiling, hook_data):
    ql.log.info("acquire_sta_object, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def GPAppLib_init(ql: Qiling, hook_data):
    ql.log.info("GPAppLib_init, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def GPAppLib_appInit(ql: Qiling, hook_data):
    ql.log.info("GPAppLib_appInit, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def GPAppLib_appShutdown(ql: Qiling, hook_data):
    ql.log.info("GPAppLib_appShutdown, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def __funcs_on_exit(ql: Qiling, hook_data:'HookData'):
    ql.log.info("__funcs_on_exit, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def qsee_prng_getdata(ql: Qiling, hook_data:'HookData'):
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

def qsee_prng_seed(ql: Qiling, hook_data:'HookData'):
    ql.log.info("qsee_prng_seed, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def qsee_prng_stir(ql: Qiling, hook_data:'HookData'):
    ql.log.info("qsee_prng_stir, back to %#x", ql.arch.regs.lr)
    _ret(ql, 0)

def qsee_printf(ql: Qiling, hook_data):
    TEE_LogPrintf(ql, hook_data)

def qsee_is_ns_range(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "addr": POINTER,
        "size": INT,
    })
    addr = args['addr']
    size = args['size']
    ql.log.info("qsee_is_ns_range ptr: %#0x size:%#0x", addr, size)

    # is_mapped = False
    # for start, end, perms, info, _ in ql.mem.get_mapinfo():
    #     # Sanity check, that we are in the params
    #     if start <= addr < addr + size < end:
    #         #  and "[qsee_ns]" in info
    #         is_mapped = True
    #         break
    # if not is_mapped:
    #     ql.log.warning("qsee_is_ns_range ptr: %#0x size:%#0x not mapped", addr, size)
    # # We just lie for simplicity
    is_mapped = True

    mapped_response = 0 if is_mapped else 0xffffffff
    ql.os.fcall.cc.setReturnValue(mapped_response)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def time_getutcsec(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "dest": POINTER,
    })
    dest = args['dest']
    ql.log.info("time_getutcsec, writing to %#x", dest)
    t = time.time_ns()
    sec = t // 1_000_000_000
    nsec = t % 1_000_000_000
    
    ql.mem.write(dest, pwn.p64(((nsec & 0xFFFFFFFF) << 32) | (sec & 0xFFFFFFFF)))
    _ret(ql, 0)

def qsee_get_uptime(ql: Qiling, hook_data:'HookData'):
    # Should return ms time
    ql.log.info("qsee_get_uptime, back to %#x", ql.arch.regs.lr)
    
    # TODO: Check if we need to be more precise
    t = datetime.timedelta(seconds=1)
    ql.os.fcall.cc.setReturnValue(int(t.total_seconds() * 1000))
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def lstat(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "path": STRING,
        "stat": POINTER,
    })
    path = args['path']
    stat = args['stat']
    ql.log.info("lstat(%s)", path)
    # with pwn.context.local(binary=hook_data.emu.ta_elf):
    #     ql.mem.write(stat, pwn.flat({}))

    # TODO: We just pretend it doesn't exist
    ql.os.fcall.cc.setReturnValue(-1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

from .non_gp.qsee.qsee_mem import get_qsee_mem_manager, QseeMem, noop_callback

def qsee_open(ql: Qiling, hook_data:'HookData'):
    # Definitly not normal open syscall...
    args = ql.os.resolve_fcall_params({
        "objdid": INT,
        "dest": POINTER,
    })
    objdid = args['objdid']
    dest = args['dest']
    ql.log.info("qsee_open(%s, %#x)", objdid, dest)

    qsee_mem = get_qsee_mem_manager(hook_data.emu)
    addr = qsee_mem.new_callback(noop_callback)
    ql.mem.write(dest, pwn.p64(addr))
    _ret(ql, 0)

def qsee_is_s_tag_area(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "vmid": INT,
        "start": POINTER,
        "end": POINTER
    })
    vmid = args['vmid']
    start = args['start']
    end = args['end']
    ql.log.info("qsee_is_s_tag_area(%#x, %#0x, %#0x)", vmid, start, end)

    # TODO: For now, we just pretend it is in the vmid area
    ql.log.warning("Returning that [%#0x, %#0x) is in the vmid %#x area", start, end, vmid)
    _ret(ql, 1)

def qsee_kdf(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "a": INT,
        "b": INT,
        "label":POINTER,
        "label_len":INT,
        "salt":POINTER,
        "salt_len":INT,
        "output":POINTER,
        "output_len":INT,
    })

    # what are a and b?
    a = args['a']
    b = args['b']
    
    label_ptr = args['label']
    label_len = args['label_len']
    label = ql.mem.read(label_ptr, label_len)
    salt_ptr = args['salt']
    salt_len = args['salt_len']
    salt = ql.mem.read(salt_ptr, salt_len)
    
    # not sure if this is really output
    output_ptr = args['output']
    output_len = args['output_len']
    ql.log.info("qsee_kdf(%#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x)", a, b, label_ptr, label_len, salt_ptr, salt_len, output_ptr, output_len)
    ql.log.info("label: %s", label)
    ql.log.info("salt: %s", salt)
    ql.log.info("ret_addr: %#x", ql.arch.regs.lr)

    # TODO: This is completely done by vibes.
    data = hashlib.md5(label + salt + b"medicwashere").digest()

    r = random.Random()
    r.seed(int.from_bytes(data, "little"))
    random_data = r.getrandbits(output_len * 8)
    ql.mem.write(output_ptr, random_data.to_bytes(output_len, "little"))

    _ret(ql, 0)



INT_MASK = 0
def qsee_get_intmask(ql: Qiling, hook_data:'HookData'):
    global INT_MASK
    args = ql.os.resolve_fcall_params({
        "intmask": POINTER,
    })
    intmask = args['intmask']
    ql.log.debug("qsee_get_intmask(%#x)", intmask)
    ql.mem.write(intmask, pwn.p32(INT_MASK))
    _ret(ql, 0)

def qsee_set_intmask(ql: Qiling, hook_data:'HookData'):
    global INT_MASK
    args = ql.os.resolve_fcall_params({
        "intmask": INT,
    })
    intmask = args['intmask']
    ql.log.debug("qsee_set_intmask(%#x)", intmask)
    INT_MASK = intmask
    _ret(ql, 0)

def qsee_disable_all_interrupts(ql: Qiling, hook_data:'HookData'):
    global INT_MASK
    INT_MASK = 0
    _ret(ql, 0)


SECURE_STATE = 0x39393939 & ~0x1
def qsee_get_secure_state(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "dst": POINTER,
    })
    dst = args['dst']
    ql.log.debug("qsee_get_secure_state(%#x)", dst)
    # (val >> 5) & 1 == 0, to indicate  RPBM key is provisioned
    ql.mem.write(dst, pwn.p32(SECURE_STATE & ~(1 << 5)))
    _ret(ql, 0)

from .non_gp.qsee.stor_device import qsee_stor_device_init, qsee_stor_open_partition, qsee_stor_read_sectors, qsee_stor_write_sectors, qsee_stor_device_get_info

### GPIO for mst.elf ###

@dataclass()
class GPIO_Output:
    gpio_num: int
    name: str
    out: str = ""
    config: int = 0

GPIO_NAME_TO_ID = {}
GPIO_OUTPUTS: dict[int, GPIO_Output] = {}
def qsee_tlmm_get_gpio_id(ql: Qiling, hook_data:'HookData'):
    global GPIO_NAME_TO_ID
    args = ql.os.resolve_fcall_params({
        "gpio_name": STRING,
        "gpio_id_out":POINTER, # uint32 ptr
    })
    gpio_name = args['gpio_name']
    gpio_id_out = args['gpio_id_out']
    ql.log.debug("qsee_tlmm_get_gpio_id(%s, %#x)", gpio_name, gpio_id_out)

    gpio_id = GPIO_NAME_TO_ID.get(gpio_name, len(GPIO_NAME_TO_ID) + 0x01)
    GPIO_NAME_TO_ID[gpio_name] = gpio_id
    GPIO_OUTPUTS[gpio_id] = GPIO_Output(gpio_id, gpio_name)

    ql.mem.write(gpio_id_out, pwn.p32(gpio_id))
    _ret(ql, 0)

def qsee_tlmm_release_gpio_id(ql: Qiling, hook_data:'HookData'):
    global GPIO_NAME_TO_ID
    args = ql.os.resolve_fcall_params({
        "gpio_id": INT,
    })
    gpio_id = args['gpio_id']
    ql.log.debug("qsee_tlmm_release_gpio_id(%#x)", gpio_id)
    gpio = GPIO_OUTPUTS.get(gpio_id, None)
    if gpio is None:
        ql.log.warning("qsee_tlmm_release_gpio_id(%#x) not found", gpio_id)
    else:
        GPIO_NAME_TO_ID.pop(gpio.name)
    GPIO_OUTPUTS.pop(gpio_id)
    _ret(ql, 0)

def qsee_tlmm_config_gpio_id(ql: Qiling, hook_data:'HookData'):
    global GPIO_NAME_TO_ID
    args = ql.os.resolve_fcall_params({
        "gpio_id": INT,
        "conf_ptr":POINTER, # uint64 ptr, not sure about what it does
    })
    gpio_id = args['gpio_id']
    conf_ptr = args['conf_ptr']
    ql.log.debug("qsee_tlmm_config_gpio_id(%s, %#x)", gpio_id, conf_ptr)
    conf = ql.mem.read(conf_ptr, 8)
    config = int.from_bytes(conf, "little")
    GPIO_OUTPUTS[gpio_id].config = config

    _ret(ql, 0)

def qsee_tlmm_gpio_id_out(ql: Qiling, hook_data:'HookData'):
    global GPIO_OUTPUTS
    args = ql.os.resolve_fcall_params({
        "gpio_num": INT,
        "val": INT,
    })
    gpio_num = args['gpio_num']
    val = args['val']
    ql.log.debug("qsee_tlmm_gpio_id_out(%#x, %#x)", gpio_num, val)
    
    # Kinda guessing that we can only write 1 bit at a time
    GPIO_OUTPUTS[gpio_num].out += "1" if (val & 1) else "0"
    # ql.log.info("GPIO_OUTPUTS[%#x].out: %s", gpio_num, GPIO_OUTPUTS[gpio_num].out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_spin(ql: Qiling, hook_data:'HookData'):
    global GPIO_OUTPUTS
    args = ql.os.resolve_fcall_params({
        "time_ms": INT,
    })
    time_ms = args['time_ms']

    ql.log.debug("qsee_spin(%#x)", time_ms)
    # Let's emulate fake delay in string:
    for k in GPIO_OUTPUTS:
        last = GPIO_OUTPUTS[k].out[-1] if GPIO_OUTPUTS[k].out else ""
        GPIO_OUTPUTS[k].out += last * (time_ms // 1000 - 1)

    _ret(ql, 0)

QSEE_CIPHER_PARAM_KEY  = 0
QSEE_CIPHER_PARAM_IV   = 1
QSEE_CIPHER_PARAM_MODE = 2
QSEE_CIPHER_PARAM_PAD  = 3
QSEE_CIPHER_CTXS = {}
QSEE_NEXT_CTX = 0x10000000

def _new_qsee_cipher_ctx(alg: int) -> int:
    global QSEE_NEXT_CTX

    ctx = QSEE_NEXT_CTX
    QSEE_NEXT_CTX += 0x100

    QSEE_CIPHER_CTXS[ctx] = {
        "alg": alg,
        "key": b"",
        "iv": b"",
        "mode": None,
        "pad": None,
    }

    return ctx

def qsee_cipher_init(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "alg": INT,
        "out_ctx": POINTER,
    })

    alg = args["alg"]
    out_ctx = args["out_ctx"]

    ctx = _new_qsee_cipher_ctx(alg)

    ql.log.info("qsee_cipher_init(alg=%#x, out_ctx=%#x) -> ctx=%#x", alg, out_ctx, ctx)
    ql.mem.write_ptr(out_ctx, ctx)

    _ret(ql, 0)


def qsee_cipher_set_param(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "param_id": INT,
        "data": POINTER,
        "data_len": INT,
    })

    ctx = args["ctx"]
    param_id = args["param_id"]
    data = args["data"]
    data_len = args["data_len"]

    ql.log.debug(
        "qsee_cipher_set_param(ctx=%#x, param_id=%#x, data=%#x, data_len=%#x)",
        ctx,
        param_id,
        data,
        data_len,
    )

    if ctx not in QSEE_CIPHER_CTXS:
        ql.log.warning("qsee_cipher_set_param: unknown ctx %#x, creating permissive ctx", ctx)
        QSEE_CIPHER_CTXS[ctx] = {
            "alg": None,
            "key": b"",
            "iv": b"",
            "mode": None,
            "pad": None,
        }

    st = QSEE_CIPHER_CTXS[ctx]

    if param_id == QSEE_CIPHER_PARAM_KEY:
        st["key"] = ql.mem.read(data, data_len)
        ql.log.info("  key = %s", st["key"].hex())

    elif param_id == QSEE_CIPHER_PARAM_IV:
        st["iv"] = ql.mem.read(data, data_len)
        ql.log.info("  iv = %s", st["iv"].hex())

    elif param_id == QSEE_CIPHER_PARAM_MODE:
        st["mode"] = _read_u32(ql, data)
        ql.log.info("  mode = %#x", st["mode"])

    elif param_id == QSEE_CIPHER_PARAM_PAD:
        st["pad"] = _read_u32(ql, data)
        ql.log.info("  pad = %#x", st["pad"])

    else:
        ql.log.warning("qsee_cipher_set_param: unknown param_id %#x", param_id)

    _ret(ql, 0)


GLOBAL_FLAGS = 0
def qsee_set_global_flag(ql: Qiling, hook_data: "HookData"):
    global GLOBAL_FLAGS
    args = ql.os.resolve_fcall_params({
        "flag": INT,
    })
    flag = args["flag"]
    ql.log.debug("qsee_set_global_flag(%#x)", flag)
    GLOBAL_FLAGS = flag
    _ret(ql, 0)

def qsee_get_global_flag(ql: Qiling, hook_data: "HookData"):
    global GLOBAL_FLAGS
    ql.log.debug("qsee_get_global_flag()")
    _ret(ql, GLOBAL_FLAGS)
