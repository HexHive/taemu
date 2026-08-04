from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .common import crash, crash_notimpl

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf


def TEES_GetIrsFlagValue(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_IsREESharedMemory(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_CheckSecureObjectCreator(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({
        "in": POINTER, 
        "in_size": INT,
    })
    in_buf = p["in"]
    in_size = p["in_size"]
    hook_data.emu.update_shm(in_buf, in_size)
    ql.log.info(f"{hook_data.func_name} returning 1")
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_InitDriver(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


fd_counter = 5
fds = {}


def _open(ql: Qiling, hook_data):
    global fds, fd_counter
    p = ql.os.resolve_fcall_params(
        {
            "path": STRING,
        }
    )
    path = p["path"]
    ql.log.info(f"{hook_data.func_name} called for {path} returning fd {fd_counter}")
    ql.os.fcall.cc.setReturnValue(fd_counter)
    fds[fd_counter] = path
    fd_counter += 1
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def _write(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": INT, "buf": POINTER, "len": INT})
    fd = p["fd"]
    if fd not in fds:
        if hook_data.emu.tee == "optee":
            ql.log.info(f"write: fd {fd}")
            if fd == 2:
                buf = p["buf"]
                lenn = p["len"]
                data = ql.mem.read(buf, lenn)
                ql.log.info(f"[optee write to stderr] {data}")
                ql.os.fcall.cc.setReturnValue(p["len"])
                ql.arch.regs.arch_pc = ql.arch.regs.lr
                return
        else:
            ql.log.warning(f"fd {fd} not in {fds}")
            crash(ql, hook_data.func_name)
            return
    if fds[fd] == "/dev/kmsg":
        ql.os.fcall.cc.setReturnValue(p["len"])
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f"write on unknown device: {fds[fd]}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(f"write on unknown device: {fds[fd]}")
            return


def _close(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": INT})
    fd = p["fd"]
    if fd not in fds:
        ql.log.warning(f"fd {fd} not in {fds}")
        crash(ql, hook_data.func_name)
        return
    del fds[fd]
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def teegris_log_encrypt(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def OPENSSL_malloc(ql: Qiling, hook_data):
    size = ql.os.resolve_fcall_params({"size": INT})["size"]
    malloc_core(ql, size, hook_data, False)

def OPENSSL_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": INT})["ptr"]
    free_core(ql, ptr, hook_data, False)


def EVP_PKEY_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    if ptr == 0:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f"EVP free on actual EVP key.. {hex(ptr)}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"EVP free on actual EVP key..")
            return


def EC_KEY_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    if ptr == 0:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f"EVP free on actual EVP key.. {hex(ptr)}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"EVP free on actual EVP key..")
            return


def EC_POINT_free(ql: Qiling, hook_data):
    ptr = ql.os.resolve_fcall_params({"ptr": POINTER})["ptr"]
    if ptr == 0:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    else:
        ql.log.warning(f"EVP free on actual EVP key.. {hex(ptr)}")
        if hook_data.emu.crash_on_not_implemented:
            crash_notimpl(ql, f"EVP free on actual EVP key..")
            return


def TEES_RPMBCheckEnable(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_RPMBRead(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def hdm_ICCC_check(ql: Qiling, hook_data):
    ql.log.info(f"hooking hdm ICCC Check, returning expected value")
    ql.os.fcall.cc.setReturnValue(0x19)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def mpos_ICCC_check(ql: Qiling, hook_data):
    ql.log.info(f"hooking hdm ICCC Check, returning expected value")
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def nanosleep(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TA_Communication_mpos_check_iccc(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"result": POINTER})["result"]
    ql.mem.write(p, (0).to_bytes(4, "little"))
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_TUIOpenSession(ql, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_TUIDrawImage(ql, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
