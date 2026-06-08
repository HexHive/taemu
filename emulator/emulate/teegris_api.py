from enum import Enum
import os
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from .common import crash, crash_notimpl

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf

def TEES_GetClientCredentials(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"out": POINTER})
    ql.mem.write_ptr(p["out"], 0x133)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def vltkpr_authenticate_ca_softpass(ql: Qiling, hook_data):
    # Phase-B model of vltkpr's PROCA soft-pass. On a custom-kernel /
    # PROCA-stripped device vk_authenticate_ca (RE @0x1a6a0) returns 0 and
    # TA_InvokeCommandEntryPoint dispatches to vk_switcher. The emulator has no
    # PROCA driver (ioctl on /dev/pa_driver is unmodeled -> emu_stop), so we
    # model the documented soft-pass directly via an inline address hook.
    # See RE/samsung_teegris/vltkpr.md "Caller authentication" (returns
    # 0 / 0x110019 custom-kernel / 0x120000 no-PROCA all proceed).
    ql.log.info("[vltkpr] vk_authenticate_ca stubbed -> 0 (PROCA soft-pass)")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_GetIrsFlagValue(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def TEES_IsREESharedMemory(ql: Qiling, hook_data):
    ql.log.info(f"{hook_data.func_name} returning 0")
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_DeriveKeyKDF(ql: Qiling, hook_data):
    # Samsung TEE syscall: derive key material from the HW device-bound root
    # key into both an out-buffer and a transient object handle.
    # Signature (RE/samsung_teegris/fbckmr.md fk_custom_so_derive_key @0x130CC):
    #   TEES_DeriveKeyKDF(salt, salt_len, out_buf, out_len, key_len, obj_handle)
    # The emulator has no HW root key, so we derive a deterministic,
    # length-correct surrogate (SHA256 chain over the salt). Correctness is
    # irrelevant to the downstream GCM overflow — only the *length* and the
    # object becoming initialized matter so TEE_GetObjectBufferAttribute and
    # the subsequent EVP_*Init_ex/EVP_DecryptUpdate path proceed.
    import hashlib
    from .gp.utils.object import handle2obj
    from .gp.utils.attribute import ATTRIBUTE_MEM
    p = ql.os.resolve_fcall_params({"salt": POINTER, "salt_len": INT, "out": POINTER,
                                    "out_len": INT, "key_len": INT, "obj": POINTER})
    salt = b""
    try:
        if p["salt"] and p["salt_len"]:
            salt = bytes(ql.mem.read(p["salt"], p["salt_len"]))
    except unicorn.unicorn_py3.unicorn.UcError:
        pass
    key_len = p["key_len"] or p["out_len"] or 32
    derived = b""
    i = 0
    while len(derived) < key_len:
        derived += hashlib.sha256(b"TEEGRIS-EMU-KDF" + salt + bytes([i & 0xFF])).digest()
        i += 1
    derived = derived[:key_len]
    ql.log.info(f"TEES_DeriveKeyKDF: salt_len={p['salt_len']} key_len={key_len} "
                f"obj={hex(p['obj'])} -> derived {len(derived)}B (surrogate)")
    try:
        if p["out"]:
            ql.mem.write(p["out"], derived)
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    obj_handle = p["obj"]
    if obj_handle in handle2obj:
        obj = handle2obj[obj_handle]
        kb = ql.mem.map_anywhere(0x1000, minaddr=ATTRIBUTE_MEM, perms=3, info="derived_key")
        ql.mem.write(kb, derived)
        obj.attrs[0xC0000000] = (kb, key_len)   # TEE_ATTR_SECRET_VALUE
        obj.key = derived
        obj.initialized = True
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

def TEES_FiniDriver(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

fd_counter = 5
fds = {}


def _parse_flags(flags:int):
    all_possible_flags = {k[2:]:v for k, v in vars(os).items() if isinstance(v, int) and k.startswith("O_")}
    return [flag for flag, v in all_possible_flags.items() if flags & v]

def _open(ql: Qiling, hook_data):
    global fds, fd_counter
    p = ql.os.resolve_fcall_params(
        {
            "path": STRING,
            "flags": INT,
        }
    )
    
    path = p["path"]
    flags = p["flags"]
    parsed_flags = _parse_flags(flags)
    ql.log.info(f"{hook_data.func_name} called for {path} ({parsed_flags}) returning fd {fd_counter}")
    
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
