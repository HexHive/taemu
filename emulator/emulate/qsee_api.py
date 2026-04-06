from collections import defaultdict
from dataclasses import dataclass
import datetime
from enum import Enum
import functools
import hashlib
import os
import random
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


class SetupTeardownAction(Enum):
    SETUP = 0
    TEARDOWN = 1


class QseeCmdIdent(Enum):
    Cmd0 = 0
    Cmd1 = 1
    Cmd2 = 2
    Cmd3 = 3
    Cmd4 = 4

class QseeTzCmdIdent(Enum):
    Cmd0 = 0
    Cmd1 = 1

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
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_prng_stir(ql: Qiling, hook_data:'HookData'):
    ql.log.info("qsee_prng_stir, back to %#x", ql.arch.regs.lr)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_printf(ql: Qiling, hook_data):
    TEE_LogPrintf(ql, hook_data)

def qsee_is_ns_range(ql: Qiling, hook_data:'HookData'):
    # TODO: Assume, that
    args = ql.os.resolve_fcall_params({
        "addr": POINTER,
        "size": INT,
    })
    addr = args['addr']
    size = args['size']
    ql.log.info("qsee_is_ns_range ptr: %#0x size:%#0x", addr, size)

    is_mapped = False
    for start, end, perms, info, _ in ql.mem.get_mapinfo():
        # Sanity check, that we are in the params
        if start <= addr < addr + size < end and "[qsee_ns]" in info:
            is_mapped = True
            break
    if not is_mapped:
        ql.log.warning("qsee_is_ns_range ptr: %#0x size:%#0x not mapped", addr, size)
    
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
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

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

def qsee_open(ql: Qiling, hook_data:'HookData'):
    # Definitly not normal open syscall...
    args = ql.os.resolve_fcall_params({
        "objdid": INT,
        "dest": POINTER,
    })
    objdid = args['objdid']
    dest = args['dest']
    ql.log.info("qsee_open(%s, %#x)", objdid, dest)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

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
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

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

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr



INT_MASK = 0
def qsee_get_intmask(ql: Qiling, hook_data:'HookData'):
    global INT_MASK
    args = ql.os.resolve_fcall_params({
        "intmask": POINTER,
    })
    intmask = args['intmask']
    ql.log.info("qsee_get_intmask(%#x)", intmask)
    ql.mem.write(intmask, pwn.p32(INT_MASK))
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_set_intmask(ql: Qiling, hook_data:'HookData'):
    global INT_MASK
    args = ql.os.resolve_fcall_params({
        "intmask": INT,
    })
    intmask = args['intmask']
    ql.log.info("qsee_set_intmask(%#x)", intmask)
    INT_MASK = intmask
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_disable_all_interrupts(ql: Qiling, hook_data:'HookData'):
    global INT_MASK
    INT_MASK = 0
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


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
    ql.log.info("qsee_tlmm_get_gpio_id(%s, %#x)", gpio_name, gpio_id_out)

    gpio_id = GPIO_NAME_TO_ID.get(gpio_name, len(GPIO_NAME_TO_ID) + 0x01)
    GPIO_NAME_TO_ID[gpio_name] = gpio_id
    GPIO_OUTPUTS[gpio_id] = GPIO_Output(gpio_id, gpio_name)

    ql.mem.write(gpio_id_out, pwn.p32(gpio_id))
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_tlmm_release_gpio_id(ql: Qiling, hook_data:'HookData'):
    global GPIO_NAME_TO_ID
    args = ql.os.resolve_fcall_params({
        "gpio_id": INT,
    })
    gpio_id = args['gpio_id']
    ql.log.info("qsee_tlmm_release_gpio_id(%#x)", gpio_id)
    gpio = GPIO_OUTPUTS.get(gpio_id, None)
    if gpio is None:
        ql.log.warning("qsee_tlmm_release_gpio_id(%#x) not found", gpio_id)
    else:
        GPIO_NAME_TO_ID.pop(gpio.name)
    GPIO_OUTPUTS.pop(gpio_id)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_tlmm_config_gpio_id(ql: Qiling, hook_data:'HookData'):
    global GPIO_NAME_TO_ID
    args = ql.os.resolve_fcall_params({
        "gpio_id": INT,
        "conf_ptr":POINTER, # uint64 ptr, not sure about what it does
    })
    gpio_id = args['gpio_id']
    conf_ptr = args['conf_ptr']
    ql.log.info("qsee_tlmm_config_gpio_id(%s, %#x)", gpio_id, conf_ptr)
    conf = ql.mem.read(conf_ptr, 8)
    config = int.from_bytes(conf, "little")
    GPIO_OUTPUTS[gpio_id].config = config

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_tlmm_gpio_id_out(ql: Qiling, hook_data:'HookData'):
    global GPIO_OUTPUTS
    args = ql.os.resolve_fcall_params({
        "gpio_num": INT,
        "val": INT,
    })
    gpio_num = args['gpio_num']
    val = args['val']
    ql.log.info("qsee_tlmm_gpio_id_out(%#x, %#x)", gpio_num, val)
    
    # Kinda guessing that we can only write 1 bit at a time
    GPIO_OUTPUTS[gpio_num].out += "1" if (val & 1) else "0"
    ql.log.info("GPIO_OUTPUTS[%#x].out: %s", gpio_num, GPIO_OUTPUTS[gpio_num].out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def qsee_spin(ql: Qiling, hook_data:'HookData'):
    global GPIO_OUTPUTS
    args = ql.os.resolve_fcall_params({
        "time_ms": INT,
    })
    time_ms = args['time_ms']

    ql.log.info("qsee_spin(%#x)", time_ms)
    # Let's emulate fake delay in string:
    for k in GPIO_OUTPUTS:
        last = GPIO_OUTPUTS[k].out[-1] if GPIO_OUTPUTS[k].out else ""
        GPIO_OUTPUTS[k].out += last * (time_ms // 1000 - 1)

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
