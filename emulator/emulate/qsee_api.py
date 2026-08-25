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
from .non_gp.qsee.api_common import _ret, _read_u32, _log_args, nonfaithful
from .non_gp.qsee.api_shared_buffers import *
from .non_gp.qsee.api_cfg import *
from .non_gp.qsee.api_stor_device import *
from .non_gp.qsee.api_crypto import *

if TYPE_CHECKING:
    from .emulator_no_loader import HookData

from . import asan
import unicorn


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
        ql.log.debug("qsee_log: lvl: %d, fmt: %s", log_level, format_param)
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
    # free_core's signature is (ql, ptr, hook_data, called_from_api_emu); it does
    # not resolve the pointer itself. Same shape as gp_api.free / TEE_Free.
    ptr = ql.os.resolve_fcall_params({"ptr": INT})["ptr"]
    free_core(ql, ptr, hook_data, False)

def sm2_encrypt(ql: Qiling, hook_data):
    _ret(ql, 0)

def calcsm3(ql: Qiling, hook_data):
    _ret(ql, 0)

def sm4_crypt(ql: Qiling, hook_data):
    _ret(ql, 0)

def cmnlib_init(ql: Qiling, hook_data):
    dest = ql.os.resolve_fcall_params({
        "dest": POINTER, # uint32_t*
    })
    dest = dest['dest']
    ql.log.info("cmnlib_init(dest=%#x)", dest)
    if (dest & 0xffff0000) != 0x20000:
        # mimicking the behavior of the real cmnlib_init
        ql.log.warning("cmnlib_init(dest=%#x) is not a valid destination", dest)
    ql.mem.write(dest, pwn.p32(0))

    _ret(ql, 0)

def cmnlib_release(ql: Qiling, hook_data):
    ql.log.info("cmnlib_release, back to %#x", ql.arch.regs.lr)
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


def qsee_err_fatal(ql: Qiling, hook_data:'HookData'):
    ql.log.critical("stack_chk_fail ***stack smashing detected***")
    crash(ql, hook_data.func_name)


def qsee_prng_getdata(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "dest": POINTER,
        "size": INT,
    })

    dest = args['dest']
    size = args['size']
    ql.mem.write(dest, os.urandom(size))

    ql.log.info("qsee_prng_getdata(dest=%#x, size=%#x)", dest, size)
    ql.os.fcall.cc.setReturnValue(args['size'])
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_get_random_bytes(ql: Qiling, hook_data:'HookData'):
    return qsee_prng_getdata(ql, hook_data)

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
    _log_args(ql, "qsee_is_ns_range", args)
    # is_mapped = False
    for start, end, perms, info, _ in ql.mem.get_mapinfo():
        # Sanity check, that we are in the params
        if start <= addr < addr + size < end:
            #  and "[qsee_ns]" in info
            is_mapped = True
            break
    if not is_mapped:
        ql.log.warning("qsee_is_ns_range ptr: %#0x size:%#0x not mapped", addr, size)
    # We just lie for simplicity
    is_mapped = True

    mapped_response = 0 if is_mapped else 0xffffffff
    ql.os.fcall.cc.setReturnValue(mapped_response)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def time_getutcsec(ql: Qiling, hook_data:'HookData'):
    args = ql.os.resolve_fcall_params({
        "dest": POINTER,
    })
    dest = args['dest']
    _log_args(ql, "time_getutcsec", args)
    t = time.time_ns()
    sec = t // 1_000_000_000
    nsec = t % 1_000_000_000
    
    ql.mem.write(dest, pwn.p64(((nsec & 0xFFFFFFFF) << 32) | (sec & 0xFFFFFFFF)))
    _ret(ql, 0)

@nonfaithful
def qsee_get_uptime(ql: Qiling, hook_data:'HookData'):
    # Should return ms time
    ql.log.info("qsee_get_uptime, back to %#x", ql.arch.regs.lr)
    
    # TODO: Check if we need to be more precise
    t = datetime.timedelta(seconds=1)
    ql.os.fcall.cc.setReturnValue(int(t.total_seconds() * 1000))
    ql.arch.regs.arch_pc = ql.arch.regs.lr

@nonfaithful
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

from .non_gp.qsee.models import HookData, get_active_qsee_session_state

def qsee_open(ql: Qiling, hook_data:'HookData'):
    # Definitly not normal open syscall...
    args = ql.os.resolve_fcall_params({
        "objdid": INT,
        "dest": POINTER,
    })
    objdid = args['objdid']
    dest = args['dest']
    ql.log.info("qsee_open(%s, %#x)", objdid, dest)

    qsee_state = get_active_qsee_session_state(hook_data.emu)
    obj = qsee_state.open_object(ql, hook_data.emu, objdid)
    ql.log.debug("object opened: %#x", obj.addr)
    ql.mem.write(dest, pwn.p64(obj.addr))
    _ret(ql, 0)

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
    _log_args(ql, "qsee_kdf", args)
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

def qsee_cipher_init(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "alg": INT,
        "out_ctx": POINTER,
    })

    alg = args["alg"]
    out_ctx = args["out_ctx"]

    ctxbuf = malloc_core(ql, 0x100, hook_data, True)
    if ctxbuf == 0:
        ql.log.error("qsee_cipher_init: failed to allocate ctx buffer")
        return _ret(ql, -1)
    
    QSEE_CIPHER_CTXS[ctxbuf] = {
        "alg": alg,
        "key": b"",
        "iv": b"",
        "mode": None,
        "pad": None,
    }
    ql.log.info("qsee_cipher_init(alg=%#x, out_ctx=%#x) -> ctx=%#x", alg, out_ctx, ctxbuf)
    ql.mem.write_ptr(out_ctx, ctxbuf)

    _ret(ql, 0)

def qsee_cipher_free_ctx(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
    })
    _log_args(ql, "qsee_cipher_free_ctx", args)
    ctx = args["ctx"]
    if ctx not in QSEE_CIPHER_CTXS:
        ql.log.warning("qsee_cipher_free_ctx: unknown ctx %#x", ctx)
    else:
        QSEE_CIPHER_CTXS.pop(ctx)
    free_core(ql, ctx, hook_data, True)
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
    _log_args(ql, "qsee_cipher_set_param", args)

    if ctx not in QSEE_CIPHER_CTXS:
        ql.log.warning("qsee_cipher_set_param: unknown ctx %#x, creating permissive ctx, which is not malloced!", ctx)
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

@nonfaithful
def qsee_cipher_encrypt(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "data": POINTER,
        "data_len": INT,
        "out": POINTER,
    })
    ctx = args["ctx"]
    data = args["data"]
    data_len = args["data_len"]
    out = args["out"]
    ql.log.debug("qsee_cipher_encrypt(ctx=%#x, data=%#x, data_len=%#x, out=%#x)", ctx, data, data_len, out)
    ql.mem.write(out, ql.mem.read(data, data_len))
    _ret(ql, 0)

@nonfaithful
def qsee_cipher_decrypt(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "data": POINTER,
        "data_len": INT,
        "out": POINTER,
    })
    ctx = args["ctx"]
    data = args["data"]
    data_len = args["data_len"]
    out = args["out"]
    ql.log.debug("qsee_cipher_decrypt(ctx=%#x, data=%#x, data_len=%#x, out=%#x)", ctx, data, data_len, out)
    ql.mem.write(out, ql.mem.read(data, data_len))
    _ret(ql, 0)

@nonfaithful
def qsee_hmac(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "ctx": POINTER,
        "data": POINTER,
        "data_len": INT,
        "out": POINTER,
    })
    ctx = args["ctx"]
    data = args["data"]
    data_len = args["data_len"]
    out = args["out"]
    ql.log.debug("qsee_hmac(ctx=%#x, data=%#x, data_len=%#x, out=%#x)", ctx, data, data_len, out)
    ql.mem.read(data, data_len)
    ql.mem.write(out, bytes(range(0x20)))
    _ret(ql, 0)

@nonfaithful
def qsee_set_bandwidth(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "client_name": STRING,
        "client_name_len": INT,
        "bus_id?": INT,
        "value?": INT,
        "flags?": INT,
    })
    client_name = args["client_name"]
    client_name_len = args["client_name_len"]
    if len(client_name) != args["client_name_len"]:
        ql.log.warning("qsee_set_bandwidth: client_name length mismatch %d != %d", len(client_name), client_name_len)
    _log_args(ql, "qsee_set_bandwidth", args)
    _ret(ql, 0)

GLOBAL_FLAGS = 0
def qsee_set_global_flag(ql: Qiling, hook_data: "HookData"):
    global GLOBAL_FLAGS
    args = ql.os.resolve_fcall_params({
        "flag": INT,
    })
    flag = args["flag"]
    _log_args(ql, "qsee_set_global_flag", args)
    GLOBAL_FLAGS = flag
    _ret(ql, 0)

def qsee_get_global_flag(ql: Qiling, hook_data: "HookData"):
    global GLOBAL_FLAGS
    _log_args(ql, "qsee_get_global_flag", {})
    _ret(ql, GLOBAL_FLAGS)


def qsee_util_init_s_bigint(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "out": POINTER,
    })
    _log_args(ql, "qsee_util_init_s_bigint", args)
    out = args["out"]
    if out == 0:
        return _ret(ql, pwn.p32(-6, sign="signed"))
    
    addr = malloc_core(ql, 0x20c, hook_data, True)
    # if addr == 0 -> return -5
    ql.mem.write(addr, 0x20c * b"\x00")
    ql.mem.write_ptr(out, addr)
    _ret(ql, 0)


def qsee_util_free_s_bigint(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "bigint": POINTER,
    })
    bigint = args["bigint"]
    ql.log.debug("qsee_util_free_s_bigint(%#x)", bigint)
    free_core(ql, bigint, hook_data, True)
    _ret(ql, 0)

def qsee_spi_close(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "spi_id": INT,
    })
    _log_args(ql, "qsee_spi_close", args)
    _ret(ql, 0)

# WARNING: This is some Quasi-Encapsulation. Useless if app only need decapsulation of the messages. Needs more investigation.
@nonfaithful
def qsee_encapsulate_inter_app_message(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "dest_app_name": STRING,
        "plain_msg": POINTER,
        "plain_msg_len": INT,
        "encap_msg_out": POINTER,
        "encap_msg_out_len": POINTER, # in + out pointer
    })
    _log_args(ql, "qsee_decapsulate_inter_app_message", args)
    input_msg = ql.mem.read(args["encap_msg_out"], args["encap_msg_out_len"])

    dest_app_name = args["dest_app_name"]
    if len(dest_app_name) > 0x80:
        ql.log.error("dest_app_name too long")
        return _ret(ql, 0xff000fff)
    
    # Our quasi encapsulation
    "Taemu Encapsulation: len dest app, len enc msg, dest app, enc msg"
    quasi_encrypted_msg = b"TE:" + struct.pack("<II", len(dest_app_name), len(input_msg)) + dest_app_name + input_msg

    available_out_buf = ql.mem.read_ptr(args["encap_msg_out_len"])
    if len(quasi_encrypted_msg) > available_out_buf:
        ql.log.error("qsee_decapsulate_inter_app_message: not enough space for output")
        return _ret(ql, 0xff000fff) # vibes based error from cmlib

    ql.mem.write(args["plain_msg"], quasi_encrypted_msg)
    ql.mem.write(args["plain_msg_len"], pwn.p32(len(quasi_encrypted_msg)))
    _ret(ql, 0)

@nonfaithful
def qsee_decapsulate_inter_app_messages(ql: Qiling, hook_data: "HookData"):
    args = ql.os.resolve_fcall_params({
        "peer_app_name_out": STRING,
        "encap_msg": POINTER,
        "encap_msg_len": INT,
        "plain_msg_out": POINTER,
        "plain_msg_out_len": POINTER,
    })
    _log_args(ql, "qsee_encapsulate_inter_app_message", args)
    input_msg = ql.mem.read(args["encap_msg"], args["encap_msg_len"])
    if len(input_msg) < 8:
        ql.log.error("input_msg too short for our Quasi Encapsulation")
        return _ret(ql, 0xff000fff)
    
    # Our quasi encapsulation
    if input_msg[:4] != b"TE:":
        ql.log.error("input_msg is not our Quasi Encapsulation")
        return _ret(ql, 0xff000fff)
    len_dest_app, len_enc_msg = struct.unpack("<I", input_msg[4:12])
    if len_dest_app + len_enc_msg + 12 > len(input_msg):
        ql.log.error("input_msg too short for our Quasi Encapsulation")
        return _ret(ql, 0xff000fff)
    
    dest_app = input_msg[12:12+len_dest_app]
    enc_msg = input_msg[12+len_dest_app:12+len_dest_app+len_enc_msg]

    if len(dest_app) > 0x80:
        ql.log.error("dest_app too long")
        return _ret(ql, 0xff000fff)

    ql.mem.write(args["peer_app_name_out"], dest_app)
    ql.mem.write(args["plain_msg_out"], enc_msg)
    ql.mem.write(args["plain_msg_out_len"], pwn.p32(len(enc_msg)))
    _ret(ql, 0)


# --- module state for the Samsung QTEE / GPAppLib models below ---------------
_WP_CFG_SIZE = int(os.environ.get("STORSEC_WPCFG", "0x3a"), 0)  # env-override for detector validation
_QSEE_CTX_BASE = 0x4EE00000
_qsee_ctx_cur = [0]
UEFI_CTL_BASE   = 0x53000000     # control page (harness-mapped)
UEFI_CTX_PTR    = 0x53001000     # dummy PKCS#7 ctx handed to the collector
UEFI_DN_PTR     = UEFI_CTL_BASE + 0x40   # shared DN bytes (memcmp match)
UEFI_DER_PTR    = UEFI_CTL_BASE + 0x80   # cert DER source bytes
UEFI_PARSED_PTR = 0x53002000     # parsed-cert struct
_MINK_BASE        = 0x4EF00000
_MINK_DISPATCH_VA = 0x4EF0F000
_mink_cur = [0]
_mink_hooked = [False]
SPU_RESP = {"len": None, "bytes": None}

# --- Samsung QTEE / GPAppLib models (from funky-experiments) -------------
# Added for statically-linked-libcmnlib TAs. Names already modelled by the
# non_gp.qsee subsystem above are intentionally NOT overridden here.
def _qsee_ok(ql: Qiling, hook_data):
    """Generic success stub: return 0, return to caller."""
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_cfg_getpropval(ql: Qiling, hook_data):
    # qsee_cfg_getpropval(name, out, ...): return "property not found" so the TA
    # takes its default branch. 0 == found could force a specific config path;
    # a non-zero keeps the generic path. Use 1 (not found / default).
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_hash(ql: Qiling, hook_data):
    # qsee_hash(alg, msg, msg_len, digest, digest_len): produce a deterministic
    # zero digest. We don't know digest_len's arg position reliably across
    # variants, so just succeed (the TA usually treats the buffer as
    # caller-sized and zero-init).
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_rsa_sign_hash(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_rsa_verify_signature(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_read_oem_buffer(ql: Qiling, hook_data):
    # qsee_read_oem_buffer(id, out, len): zero-fill, succeed.
    try:
        p = ql.os.resolve_fcall_params({"id": INT, "out": POINTER, "len": INT})
        if p["out"] and 0 < p["len"] <= 0x10000:
            ql.mem.write(p["out"], b"\x00" * p["len"])
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_write_oem_buffer(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_stor_write_wp_config(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params({"src": POINTER})
        src = p["src"]
        if src:
            # Touch the source the real primitive would consume. Use the RAW
            # unicorn mem_read (NOT ql.mem.read, which tolerantly zero-pads across
            # unmapped pages): if the handler ever hands us a source that runs off
            # its buffer (e.g. an unclamped req+innerLen), the raw read faults on
            # the guard page and we report a crash. (It is clamped today:
            # innerLen <= req_len - 0x3a, so this stays in-bounds.)
            ql.arch.uc.mem_read(src, _WP_CFG_SIZE)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_stor_read_wp_config(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params({"dst": POINTER})
        dst = p["dst"]
        if dst:
            # Write the WP-config blob the real primitive would emit. Raw unicorn
            # mem_write so an undersized / mis-pointed destination (a handler
            # response-buffer bug) faults on the guard. (Today dst = resp, which
            # the handler validates >= 0x4a, so this stays in-bounds.)
            ql.arch.uc.mem_write(dst, b"\x00" * _WP_CFG_SIZE)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


# small bump allocator for opaque ctx handles handed back by stubs above, kept
# out of the asan heap so freeing them via qsee_cipher_free_ctx (a no-op) never
# trips the heap detector.
def malloc_ctx(ql: Qiling, hook_data):
    base = _QSEE_CTX_BASE
    if _qsee_ctx_cur[0] == 0:
        try:
            ql.mem.map(base, 0x10000, info="[qsee] stub ctx pool")
        except Exception:
            pass
        _qsee_ctx_cur[0] = base
    addr = _qsee_ctx_cur[0]
    _qsee_ctx_cur[0] += 0x100
    return addr

# --- bksecapp additional service surface (S6/cmd50 bring-up) ------------------
# These appear as JUMP_SLOT imports in bksecapp; none sits on the cmd50
# BksecappKdf path (which uses only the real qsee_malloc/qsee_kdf + qsee_log +
# the real memcpy/memset internals + qsee_get_secure_state/qsee_read_oem_buffer).
# They keep the OTHER bksecapp command branches and the GP lifecycle from hitting
# an unmodeled API. Modeled as success no-ops / zero-fill identities.

def qsee_fuse_read(ql: Qiling, hook_data):
    # int qsee_fuse_read(uint32 addr, uint32 count, uint32 *out, int *err);
    # (aarch64 ABI x0=addr, x1=count, x2=out, x3=err). bksecapp cmd51/52 pass
    # count=1 (immediate) into an 8-byte stack slot, so this is NOT a corruption
    # sink -- but model the write faithfully (count words) so the value path is
    # exercised; zero-fill the fuse value (deterministic).
    out = ql.arch.regs.x2
    count = ql.arch.regs.x1 & 0xFFFFFFFF
    err = ql.arch.regs.x3
    if out and 0 < count <= 0x1000:
        try:
            ql.mem.write(out, b"\x00" * (4 * count))
        except Exception:
            pass
    if err:
        try:
            ql.mem.write(err, (0).to_bytes(4, "little"))
        except Exception:
            pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_fuse_write(ql: Qiling, hook_data):
    # int qsee_fuse_write(addr, value_ptr, flag, err): succeed, set *err=0.
    #
    # OBSERVABILITY (S7 / tz_kg fuse-blow, Q4): an IRREVERSIBLE hardware side
    # effect. We never mutate state (no fuse in the emulator), but we LOG the
    # targeted fuse address + value word so a replay of tz_kg's KGBL_write_fuse
    # path proves the NWd-forgeable request reached qsee_fuse_write(0x221C1358,
    # state). kg_write_fuse_bit@0x3d08 calls it as (x0=addr, x1=&value8, x2=0,
    # x3=&err) with [x1] high dword = state. 0x221C1358 ==
    # HWIO_QFPROM_RAW_OEM_SPARE_1_ROW1_LSB.
    addr = ql.arch.regs.x0 & 0xFFFFFFFF
    valp = ql.arch.regs.x1
    val = None
    if valp:
        try:
            val = int.from_bytes(ql.mem.read(valp, 8), "little")
        except Exception:
            val = None
    vs = hex(val) if val is not None else "?"
    if addr == 0x221C1358:
        ql.log.warning(
            f"[qsee_fuse_write] *** OEM SPARE_1 FUSE BLOW *** addr={hex(addr)} "
            f"value8={vs} (S7 KGBL_write_fuse reached)"
        )
    else:
        ql.log.info(f"[qsee_fuse_write] addr={hex(addr)} value8={vs}")
    err = ql.arch.regs.x3
    if err:
        try:
            ql.mem.write(err, (0).to_bytes(4, "little"))
        except Exception:
            pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_cipher_reset(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_read_serial_num(ql: Qiling, hook_data):
    # qsee_read_serial_num(uint32 *out): write a deterministic serial.
    try:
        p = ql.os.resolve_fcall_params({"out": POINTER})
        if p["out"]:
            ql.mem.write(p["out"], (0).to_bytes(4, "little"))
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_stor_device_init(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_stor_device_get_info(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_stor_open_partition(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_stor_add_partition(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_stor_read_sectors(ql: Qiling, hook_data):
    # qsee_stor_read_sectors(handle, lba, buf, nsec, ...): zero-fill the
    # destination if we can identify it; otherwise just succeed. bksecapp reads
    # the BKSA partition into a fixed 4096 global, so a no-op success is safe
    # (the global is pre-zeroed in guest memory).
    _qsee_ok(ql, hook_data)


def qsee_stor_write_sectors(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_stor_client_get_info(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_sfs_open(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_sfs_read(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params({"h": INT, "buf": POINTER, "len": INT})
        n = p["len"] & 0xFFFFFFFF
        if p["buf"] and 0 < n <= 0x10000:
            ql.mem.write(p["buf"], b"\x00" * n)
        ql.os.fcall.cc.setReturnValue(n)
    except Exception:
        ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_sfs_write(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params({"h": INT, "buf": POINTER, "len": INT})
        ql.os.fcall.cc.setReturnValue(p["len"] & 0xFFFFFFFF)
    except Exception:
        ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_sfs_close(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_sfs_rm(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_BIGINT_read_unsigned_bin(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


# ===========================================================================
# uefi_sec (qcom.tz.uefisecapp) S10 reproduction — inline parser stubs.
#
# Added 2026-06-17 for the QSEE fuzz wave (Q3). These model the PKCS#7 parse
# *leaves* of validate_pkcs7_and_get_public_key@0x13f28 and the cert-chain
# collector secpkcs7_get_cert_chain_from_sig_index@0xe61c so the REAL collector
# (with both S10 sinks) runs on a SYNTHESISED, attacker-shaped cert chain
# without us having to drive a full DER/ASN.1 PKCS#7 parser through emulation.
#
# Reaching the sink the faithful way: InvokeCommand is pointed at the real
# validate_pkcs7_and_get_public_key@0x13f28. It does the real qsee_malloc(0x2800)
# (asan-redzoned heap chunk -> QUEFI-7 dest) and the real memset of the 4-slot
# global g_cert_chain_records@0x23d88 (QUEFI-1 dest), then calls the real
# collector@0xe61c. We inline-stub only:
#   - 0xe208 pkcs7_secboot_hash       -> return 0   (hash ok)
#   - 0xe968 secpkcs7_new_ctx         -> return 1, write a dummy ctx ptr
#   - 0xe9f0 secpkcs7_parse_buffer    -> return 1
#   - 0xf328 secpkcs7_verify_si       -> return 1   (SELF-SIGNED passes: this IS
#                                                    the pre-trust property of S10)
# and the collector's 3 internal callees so it walks our synthetic chain:
#   - 0xe3ec u_get_si_dn (writes DN ptr/len into the x2 out-struct)
#   - 0xe8b0 u_get_cert_by_index_DER  (writes cert DER ptr + LENGTH; LENGTH is the
#                                       QUEFI-7 overflow size for the raw-bytes sink)
#   - 0xe558 u_get_parsed_cert        (writes the 2008-B parsed-cert struct ptr;
#                                       this struct is the QUEFI-1 copy source)
#
# All control values come from a fixed guest control page (UEFI_CTL_BASE) the
# harness writes per AFL input:
#   +0x00 u32 n_certs          number of chaining certs the collector will see
#   +0x04 u32 der_len          DER length reported for each cert (w24; QUEFI-7)
#   +0x08 u32 dn_match         1 => DN compares succeed (take append path)
#   +0x40        DN bytes (4)  shared issuer/subject DN bytes, so the real
#                              internal memcmp@0x15f2c returns 0 (chain links)
#   +0x80        cert DER buffer (the raw bytes QUEFI-7 concatenates)
# and a synthetic ctx / parsed-cert scratch the stubs hand back.
# ===========================================================================

def _u_ctl(ql, off):
    return int.from_bytes(ql.mem.read(UEFI_CTL_BASE + off, 4), "little")

def _u_ret(ql, val):
    ql.os.fcall.cc.setReturnValue(val)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

# --- validate_pkcs7_and_get_public_key parse leaves -------------------------

def u_pkcs7_secboot_hash(ql: Qiling, hook_data):
    # int pkcs7_secboot_hash(alg, payload, len, out_hash, hashlen) -> 0 == ok.
    _u_ret(ql, 0)

def u_secpkcs7_new_ctx(ql: Qiling, hook_data):
    # int secpkcs7_new_ctx(void **ctx_out) -> 1 == ok; hand back a dummy ctx.
    # The collector's QUEFI-1 chain-walk loop calls an indirect check_issued
    # function pointer loaded from ctx+0xa0 (0xe804: ldr x2,[x21,#0xa0];
    # 0xe808: bl 0x460 -> br x2). Point it at a `mov w0,#1; ret` gadget @0xe148
    # so check_issued returns 1 (cert chains) and the loop appends the next
    # record -> drives count past 4 (QUEFI-1). Without this the indirect call
    # branches to 0 and faults.
    out = ql.arch.regs.x0
    try:
        ql.mem.write_ptr(out, UEFI_CTX_PTR)
        base = ql.mem.get_lib_base("uefi_sec.ta")
        ql.mem.write_ptr(UEFI_CTX_PTR + 0xa0, base + 0xe148)  # check_issued -> 1
    except Exception:
        pass
    _u_ret(ql, 1)

def u_secpkcs7_parse_buffer(ql: Qiling, hook_data):
    # int secpkcs7_parse_buffer(ctx, der, der_len) -> 1 == ok.
    _u_ret(ql, 1)

def u_secpkcs7_verify_si(ql: Qiling, hook_data):
    # int secpkcs7_verify_si(ctx, idx, tbs_hash, hashlen) -> 1 == ok.
    # A self-signed PKCS#7 passes verify_si (key comes from the embedded cert,
    # NOT the trust store) -- modelling success is exactly S10's pre-trust reach.
    _u_ret(ql, 1)

# --- collector@0xe61c internal callees --------------------------------------

def u_get_si_dn(ql: Qiling, hook_data):
    # 0xe3ec: fills the x2 out-struct used by the two DN memcmps in the first
    # collector iteration. Layout consumed by the collector:
    #   [x2+0x00]=DN_ptr_A  [x2+0x08]=len_A   (2nd memcmp @0xe6ec, cbz->sink)
    #   [x2+0x10]=DN_ptr_B  [x2+0x18]=len_B   (1st memcmp @0xe6e4, cbnz->skip)
    # Point both at the shared DN bytes so both memcmps match (w0==0) and the
    # collector falls into the slot-0 sink @0xe758.
    x2 = ql.arch.regs.x2
    try:
        ql.mem.write_ptr(x2 + 0x00, UEFI_DN_PTR)
        ql.mem.write(x2 + 0x08, (4).to_bytes(8, "little"))
        ql.mem.write_ptr(x2 + 0x10, UEFI_DN_PTR)
        ql.mem.write(x2 + 0x18, (4).to_bytes(8, "little"))
    except Exception:
        pass
    _u_ret(ql, 1)

def u_get_cert_by_index_DER(ql: Qiling, hook_data):
    # 0xe8b0: int f(ctx, idx, void **der_out, u32 *len_out).
    #   [der_out] = raw cert DER ptr ; [len_out] = cert DER length (== w24).
    # The collector then does uefi_memcpy(chainbuf, der, len) and chainbuf += len
    # with NO clamp vs 0x2800 -> QUEFI-7. We return der_len from the control page
    # (the attacker-controlled length the harness drives) for idx 0; for idx >=
    # n_certs we return 6 (NO_MORE) so the count-discovery loop terminates.
    idx     = ql.arch.regs.x1 & 0xFF
    der_out = ql.arch.regs.x2
    len_out = ql.arch.regs.x3
    n       = _u_ctl(ql, 0x00)
    der_len = _u_ctl(ql, 0x04) & 0xFFFF       # 16-bit-bounded, exactly as in-TA
    if idx >= n:
        _u_ret(ql, 6)                          # PKCS7_NO_MORE_CERTS
        return
    try:
        if der_out:
            ql.mem.write_ptr(der_out, UEFI_DER_PTR)
        if len_out:
            ql.mem.write(len_out, der_len.to_bytes(4, "little"))
    except Exception:
        pass
    _u_ret(ql, 1)

def u_get_parsed_cert(ql: Qiling, hook_data):
    # 0xe558: walks one cert and returns a 2008-B pbl_secx509-parsed struct ptr
    # at [x2]. This struct is the QUEFI-1 copy source (uefi_memcpy(slot,struct,
    # 0x7d8)). Its +0x20 / +0x60 are the subject/issuer DN ptrs the 2nd-iter
    # memcmps read; point them at the shared DN bytes so chaining continues.
    x2 = ql.arch.regs.x2
    n  = _u_ctl(ql, 0x00)
    # the collector calls 0xe558 with w1 = the candidate cert idx; only return a
    # struct for in-range idxs (drives the QUEFI-1 record count = n).
    idx = ql.arch.regs.x1 & 0xFF
    if idx >= n:
        _u_ret(ql, 7)
        return
    try:
        ql.mem.write_ptr(UEFI_PARSED_PTR + 0x20, UEFI_DN_PTR)
        ql.mem.write_ptr(UEFI_PARSED_PTR + 0x60, UEFI_DN_PTR)
        ql.mem.write_ptr(x2, UEFI_PARSED_PTR)
    except Exception:
        pass
    _u_ret(ql, 1)


# ===========================================================================
# featenabler (garnet) + spu_service (houji) bring-up (Q6 fuzz wave).
#
# Both TAs reach external libcmnlib services through a Mink-style object:
# qsee_open(svc_id, &out) writes a 2-pointer object {method_ptr, this} into
# *out, and the TA later does `blr method_ptr(this, op, &args, args_len)`.
# We model that object generically: qsee_open writes {DISPATCH_HOOK, this}; the
# DISPATCH_HOOK is a hooked guest address whose handler zero-fills the reply
# slot and returns 0 (so feature counts / soc_hw_version / svc replies default
# to 0 -> the handlers take their empty/default branch, which is bounded).
#
# These defs are APPENDED so a later module-level binding wins over the simple
# earlier qsee_open (which only set a return value and never wrote *out, so
# featenabler's `blr method_ptr` would have fetched a null/garbage vtable).
# Backward-compat: we only write *out when x1 is a mapped+writable guest ptr.
# ===========================================================================

def _mink_object_dispatch(ql: Qiling, hook_data):
    """method(this=x0, op=w1, args=x2, args_len=w3) -> 0; zero-fill reply."""
    try:
        x2 = ql.arch.regs.x2
        w3 = ql.arch.regs.x3 & 0xFFFFFFFF
        if x2 and 0 < w3 <= 0x1000:
            ql.mem.write(x2, b"\x00" * w3)
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def _mink_init(ql: Qiling):
    if _mink_cur[0] == 0:
        try:
            ql.mem.map(_MINK_BASE, 0x10000, info="[mink] object pool")
        except Exception:
            pass
        try:
            ql.mem.map(_MINK_DISPATCH_VA & ~0xFFF, 0x1000, info="[mink] dispatch")
        except Exception:
            pass
        _mink_cur[0] = _MINK_BASE
    if not _mink_hooked[0]:
        ql.hook_address(_mink_object_dispatch, _MINK_DISPATCH_VA, user_data=None)
        _mink_hooked[0] = True


def _mink_new_object(ql: Qiling):
    base = _mink_cur[0]
    this = base + 0x40
    pair = base
    try:
        ql.mem.write(pair, _MINK_DISPATCH_VA.to_bytes(8, "little"))
        ql.mem.write(pair + 8, this.to_bytes(8, "little"))
        ql.mem.write(this, b"\x00" * 0x40)
    except Exception:
        pass
    _mink_cur[0] += 0x80
    if _mink_cur[0] >= _MINK_BASE + 0xF000:
        _mink_cur[0] = _MINK_BASE
    return pair


def _writable_ptr(ql: Qiling, addr):
    if not addr:
        return False
    try:
        ql.mem.read(addr, 8)
        return True
    except Exception:
        return False


def qsee_open_singleton(ql: Qiling, hook_data):
    qsee_open(ql, hook_data)


def qsee_spcom_register_client(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_spcom_unregister_client(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


def qsee_spcom_client_is_server_connected(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_spcom_client_send_message_sync(ql: Qiling, hook_data):
    # (handle, req_ptr, req_len, rsp_ptr, rsp_len_cap, timeout). Fill rsp_ptr.
    try:
        p = ql.os.resolve_fcall_params({
            "h": INT, "req": POINTER, "req_len": INT,
            "rsp": POINTER, "rsp_cap": INT, "to": INT,
        })
        rsp = p["rsp"]
        cap = p["rsp_cap"] & 0xFFFFFFFF
        if rsp and cap:
            if SPU_RESP["bytes"] is not None:
                data = SPU_RESP["bytes"][:cap]
            else:
                data = b"\x00" * min(cap, 0x40)
            ql.mem.write(rsp, data)
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_sfs_getSize(ql: Qiling, hook_data):
    try:
        p = ql.os.resolve_fcall_params({"h": INT, "out": POINTER})
        if p["out"]:
            ql.mem.write(p["out"], (0x20).to_bytes(4, "little"))
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def qsee_sfs_error(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEE_Wait(ql: Qiling, hook_data):
    _qsee_ok(ql, hook_data)


