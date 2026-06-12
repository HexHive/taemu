from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER, UINT
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *


from .determinism import get_random_bytes

from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf

fd2file = {}
STROAGE = "emulate/files/L2/"

RPMSESSIONS = {}
RPMSESSION_BUFFER_L2_MEM = 0x920000

RPMSESSIONS_L1 = None
RPMSESSION_BUFFER_L1_MEM = 0x980000

def ut_pf_rpmb_open(ql: Qiling, func_name):
    global RPMSESSIONS_L1

    ret = TEE_SUCCESS
    if RPMSESSIONS_L1 == None:
        ql.log.info("ut_pf_rpmb_open: ")
    else:
        ql.log.info("ut_pf_rpmb_open: more than one L1 rpmb session, could be wrong!")
    m = ql.mem.map_anywhere(
        0x1000, minaddr=RPMSESSION_BUFFER_L1_MEM, info="Rpmsession_L1_buffer"
    )
    RPMSESSIONS_L1 = m

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_rpmb_read_data_blocks(ql: Qiling, func_name):
    global RPMSESSIONS_L1
    params = ql.os.resolve_fcall_params(
        {"sessionID": UINT, "buf": POINTER, "size": UINT}
    )
    para_sessionID = params["sessionID"]
    para_buf = params["buf"]
    para_size = params["size"]

    if RPMSESSIONS_L1 == None:
        ql.log.info("ut_pf_rpmb_read_data_blocks: empty session")
    else:
        content = bytes(ql.mem.read(RPMSESSIONS_L1, para_size))
        ql.mem.write(para_buf, content)

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_rpmb_cp_read_data_blocks(ql: Qiling, func_name):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def mdrv_ioctl(ql: Qiling, func_name):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_rpmb_cp_write_data_blocks(ql: Qiling, func_name):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_cp_open(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_cp_close(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def get_device_info(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params(
        {"buf": POINTER, "outsize": POINTER}
    )
    para_buf = params["buf"]
    ql.mem.write_ptr(params["outsize"], 0x10)
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_rpmb_close(ql: Qiling, func_name):
    global RPMSESSIONS_L1

    ret = TEE_SUCCESS
    if RPMSESSIONS_L1 == None:
        ql.log.info("ut_pf_rpmb_close: empty session")
    else:
        ql.mem.unmap(RPMSESSIONS_L1, 0x1000)
        RPMSESSIONS_L1 = None

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def tz_log(ql: Qiling, hook_data):
    TEE_LogvPrintf(ql, hook_data)

def ut_pf_log_msg(ql: Qiling, hook_data):
    TEE_LogvPrintf(ql, hook_data)

def tz_dump_mem_info(ql: Qiling, hook_data):
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def error_set(ql: Qiling, hook_data):
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def dm_update_data_base(ql: Qiling, hook_data):
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def dm_dump_data_base(ql: Qiling, hook_data):
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def mdrv_open(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0x123)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def mdrv_close(ql: Qiling, hook_data):
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def msee_ta_printf_va(ql: Qiling, hook_data):
    TEE_LogPrintf(ql, hook_data)


def ut_pf_cp_rd_random(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"unno": INT, "buf": POINTER, "size": INT})
    buf = params["buf"]
    size = params["size"]
    if not hook_data.emu.asan.is_access_valid(
        hook_data.emu.HEAP, buf, size, hook_data.func_name, is_write=True
    ):
        return
    ql.mem.write(buf, size * b"A")
    hook_data.emu.writeback_shm(buf, size)
    ql.os.fcall.cc.setReturnValue(0x0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def paytrigger_aes_cbc(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({
        "mode1": INT, "mode2": INT, "key": POINTER, "key_size": INT,
        "iv": POINTER, "iv_size": INT, "in_buf": POINTER, "in_buf_size": INT, "out_buf": POINTER
    })
    in_buf = params["in_buf"]
    in_buf_size = params["in_buf_size"]
    out_buf = params["out_buf"]
    hook_data.emu.update_shm(in_buf)
    try:
        a = ql.mem.read(in_buf, in_buf_size) # just for checking if valid access
        ql.mem.write(out_buf, in_buf_size*b"A")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql. hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(0x0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def paytrigger_hmac(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({
        "key": POINTER, "key_size": INT,
        "iv": POINTER, "iv_size": INT, "in_buf": POINTER, "in_buf_size": INT, "out_buf": POINTER
    })
    in_buf = params["in_buf"]
    in_buf_size = params["in_buf_size"]
    out_buf = params["out_buf"]
    ql.log.info(f"paytrigger hmac in_buf: {hex(in_buf)} {hex(in_buf_size)}")
    hook_data.emu.update_shm(in_buf)
    try:
        a = ql.mem.read(in_buf, in_buf_size) # just for checking if valid access
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql. hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(0x0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_ts_cp_exist(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"name": POINTER})
    param_name = params["name"]
    hook_data.emu.update_shm(param_name)
    file_name = ql.mem.string(param_name)
    ql.log.info(f"ut_pf_ts_cp_exist, name: {file_name}")

    ret = 0
    try:
        f = open(STROAGE + file_name, "r")
        ret = 1
        f.close()
    except:
        ret = 0

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_ts_cp_open(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"name": POINTER, "flags": UINT})
    param_name = params["name"]
    param_flags = params["flags"]
    hook_data.emu.update_shm(param_name)
    file_name = ql.mem.string(param_name)
    ql.log.info(f"ut_pf_ts_cp_open: name: {file_name}, flags: {param_flags}")

    try:
        if param_flags == 0x41:
            f = open(STROAGE + file_name, "wb")
        elif param_flags == 0:
            f = open(STROAGE + file_name, "rb")
        else:
            raise ValueError("Not recognize this flag")
        fd2file[f.fileno()] = f
        ql.os.fcall.cc.setReturnValue(f.fileno())
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    except:
        ql.os.fcall.cc.setReturnValue(-1)
        ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_ts_cp_error(ql: Qiling, hook_data):
    # do nothing, return 0
    ql.log.info(f"ut_pf_ts_cp_error")

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_ts_cp_write(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"fd": UINT, "buffer": POINTER, "len": UINT})
    param_fd = params["fd"]
    param_buffer = params["buffer"]
    param_len = params["len"]

    hook_data.emu.update_shm(param_buffer, param_len)
    ql.log.info(f"ut_pf_ts_cp_write: write {param_len} bytes to file {param_fd}")

    ret = 0
    if param_fd not in fd2file:
        ret = -1
        ql.log.info(f"ut_pf_ts_cp_write: {param_fd} not in {fd2file}")
    else:
        try:
            file = fd2file[param_fd]
            content = ql.mem.read(param_buffer, param_len)
            file.write(content)
            ret = param_len
            ql.log.info(f"ut_pf_ts_cp_write: write {ret} bytes")
        except Exception as e:
            ql.log.info(f"ut_pf_ts_cp_write failed: {e}")
            ret = -1

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_ts_cp_read(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"fd": UINT, "buffer": POINTER, "len": UINT})
    param_fd = params["fd"]
    param_buffer = params["buffer"]
    param_len = params["len"]

    ql.log.info(f"ut_pf_ts_cp_read: read {param_len} bytes from file {param_fd}")

    ret = 0
    if param_fd not in fd2file:
        ret = 0
        ql.log.info(f"ut_pf_ts_cp_read: {param_fd} not in {fd2file}")
    else:
        try:
            file = fd2file[param_fd]
            content = file.read()
            if len(content) > param_len:
                ret = param_len
            else:
                ret = len(content)
            ql.log.info(f"ut_pf_ts_cp_read: read {ret} bytes: {content}")
            ql.mem.write(param_buffer, content)
        except:
            ret = 0
    hook_data.emu.writeback_shm(param_buffer, param_len)
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_ts_cp_close(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({"fd": UINT})
    param_fd = params["fd"]

    ret = 0
    if param_fd not in fd2file:
        ret = -1
    else:
        try:
            fd2file[param_fd].close()
            del fd2file[param_fd]
            ret = 0
        except:
            ret = -1

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

# --- ut_pf trusted-storage: the corpus imports both the `_cp_` verbs and their
# base aliases, plus size/lseek/mkdir/rename/unlink which weren't modelled.
# Back them with the same flat STROAGE files + fd2file table as the _cp_ set,
# so a TA that uses trusted storage in OpenSession/Invoke runs instead of dying.
def ut_pf_ts_cp_size(ql: Qiling, hook_data):
    fd = ql.os.resolve_fcall_params({"fd": UINT})["fd"]
    sz = 0
    f = fd2file.get(fd)
    if f:
        try:
            cur = f.tell(); f.seek(0, 2); sz = f.tell(); f.seek(cur)
        except Exception:
            sz = 0
    ql.os.fcall.cc.setReturnValue(sz)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_ts_cp_lseek(ql: Qiling, hook_data):
    p = ql.os.resolve_fcall_params({"fd": UINT, "off": INT, "whence": INT})
    f = fd2file.get(p["fd"])
    pos = -1
    if f:
        try:
            f.seek(p["off"], p["whence"]); pos = f.tell()
        except Exception:
            pos = -1
    ql.os.fcall.cc.setReturnValue(pos)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_ts_mkdir(ql: Qiling, hook_data):
    import os
    name = ql.mem.string(ql.os.resolve_fcall_params({"name": POINTER})["name"])
    try:
        os.makedirs(STROAGE + name, exist_ok=True)
    except Exception:
        pass
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_ts_rename(ql: Qiling, hook_data):
    import os
    p = ql.os.resolve_fcall_params({"old": POINTER, "new": POINTER})
    try:
        os.rename(STROAGE + ql.mem.string(p["old"]), STROAGE + ql.mem.string(p["new"]))
        ret = 0
    except Exception:
        ret = -1
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_ts_unlink(ql: Qiling, hook_data):
    import os
    name = ql.mem.string(ql.os.resolve_fcall_params({"name": POINTER})["name"])
    try:
        os.remove(STROAGE + name); ret = 0
    except Exception:
        ret = -1
    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

# base-name aliases of the _cp_ trusted-storage verbs
def ut_pf_ts_open(ql: Qiling, hook_data):  ut_pf_ts_cp_open(ql, hook_data)
def ut_pf_ts_close(ql: Qiling, hook_data): ut_pf_ts_cp_close(ql, hook_data)
def ut_pf_ts_read(ql: Qiling, hook_data):  ut_pf_ts_cp_read(ql, hook_data)
def ut_pf_ts_write(ql: Qiling, hook_data): ut_pf_ts_cp_write(ql, hook_data)
def ut_pf_ts_exist(ql: Qiling, hook_data): ut_pf_ts_cp_exist(ql, hook_data)
def ut_pf_ts_size(ql: Qiling, hook_data):  ut_pf_ts_cp_size(ql, hook_data)
def ut_pf_ts_lseek(ql: Qiling, hook_data): ut_pf_ts_cp_lseek(ql, hook_data)

# correctly-spelled RPMB session open (the bundled name had a typo:
# TEE_RpbmOpenSession); delegate to the real implementation in custom/rpmb.py.
def TEE_RpmbOpenSession(ql: Qiling, hook_data):
    rpmb.TEE_RpmbOpenSession(ql, hook_data)

def msee_get_system_free_memory(ql: Qiling, hook_data):
    # report a plausible amount of free heap (1 MiB) so size checks pass
    ql.os.fcall.cc.setReturnValue(0x100000)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_km_get_hmac_key(ql: Qiling, func_name):
    # will go into subroutine so lr needs to be recorded
    current_lr = ql.arch.regs.lr
    # ql.arch.regs.arch_sp -= 0x38

    params = ql.os.resolve_fcall_params({"a1": UINT, "a2": POINTER})
    a1 = params["a1"]
    a2 = params["a2"]
    hmac_size = ql.mem.read_ptr(a2)

    ql.log.info(f"ut_pf_km_get_hmac_key {hex(a1)}, {hex(a2)}, {hex(hmac_size)}")

    ql.mem.write(a1, b"a" * hmac_size)
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = current_lr

def dm_data_base_init(ql: Qiling, func_name):
    ql.arch.regs.arch_pc = ql.arch.regs.lr