from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER, UINT
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *


from Crypto.Random import get_random_bytes

from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf

fd2file = {}
STROAGE = "emulate/files/L2/"

def ut_pf_log_msg(ql: Qiling, hook_data):
    TEE_LogvPrintf(ql, hook_data)

def mdrv_open(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0x123)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def mdrv_close(ql: Qiling, hook_data):
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def msee_ta_printf_va(ql: Qiling, hook_data):
    TEE_LogPrintf(ql, hook_data)

def ut_pf_cp_rd_random(ql: Qiling, hook_data):
    params = ql.os.resolve_fcall_params({'int': INT, 'buf': POINTER, 'size': INT})
    buf = params['buf']
    size = params['size']
    if not asan.is_access_valid(
        ql, hook_data.emu.HEAP, buf, size, hook_data.func_name, is_write=True
    ):
        return
    ql.mem.write(buf, size * b"A")
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_ts_cp_exist(ql:Qiling, func_name):
    params = ql.os.resolve_fcall_params({'name': POINTER})
    param_name = params['name']

    file_name = ql.mem.string(param_name)
    ql.log.info(f"ut_pf_ts_cp_exist, name: {file_name}")

    ret = 0
    try:
        f = open(STROAGE + file_name, 'r')
        ret = 1
        f.close()
    except:
        ret = 0

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def ut_pf_ts_cp_open(ql:Qiling, func_name):
    params = ql.os.resolve_fcall_params({'name': POINTER, 'flags': UINT})
    param_name = params['name']
    param_flags = params['flags']

    file_name = ql.mem.string(param_name)
    ql.log.info(f"ut_pf_ts_cp_open: name: {file_name}, flags: {param_flags}")

    try:
        if param_flags == 0x41:
            f = open(STROAGE + file_name, 'wb')
        elif param_flags == 0:
            f = open(STROAGE + file_name, 'rb')
        else:
            raise ValueError("Not recognize this flag")
        fd2file[f.fileno()] = f
        ql.os.fcall.cc.setReturnValue(f.fileno())
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    except:
        ql.os.fcall.cc.setReturnValue(-1)
        ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_ts_cp_error(ql:Qiling, func_name):
    # do nothing, return 0
    ql.log.info(f"ut_pf_ts_cp_error")

    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr



def ut_pf_ts_cp_write(ql:Qiling, func_name):
    params = ql.os.resolve_fcall_params({'fd': UINT, 'buffer': POINTER, 'len': UINT})
    param_fd = params['fd']
    param_buffer = params['buffer']
    param_len = params['len']

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

def ut_pf_ts_cp_read(ql:Qiling, func_name):
    params = ql.os.resolve_fcall_params({'fd': UINT, 'buffer': POINTER, 'len': UINT})
    param_fd = params['fd']
    param_buffer = params['buffer']
    param_len = params['len']

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

    ql.os.fcall.cc.setReturnValue(ret)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def ut_pf_ts_cp_close(ql:Qiling, func_name):
    params = ql.os.resolve_fcall_params({'fd': UINT})
    param_fd = params['fd']

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
