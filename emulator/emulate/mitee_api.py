from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *
from Crypto.Random import get_random_bytes
from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE
import time as pytime

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf, TEE_MemCompare

def zx_check_memory_access_rights(ql: Qiling, hook_data):
    ql.log.info(
        f'{hook_data.func_name} returning 0'
    )
    out = ql.os.resolve_fcall_params({"perm": INT, "buf": POINTER, "size": POINTER, "out": POINTER})["out"]
    ql.os.fcall.cc.setReturnValue(0)
    ql.mem.write(out, (0).to_bytes(4, "little"))
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def consttime_memcmp(ql: Qiling, hook_data):
    TEE_MemCompare(ql, hook_data)

def time(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(int(pytime.time()))
    ql.arch.regs.arch_pc = ql.arch.regs.lr
