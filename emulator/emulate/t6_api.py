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
from .common import crash

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf, TEE_MemCompare, malloc, free

def GetBootSeed(ql: Qiling, hook_data):
    ql.log.info(
        f'{hook_data.func_name} returning 0'
    )
    out = ql.os.resolve_fcall_params({"buf": POINTER, "size": INT})
    buf = out["buf"]
    size = out["size"]
    try:
        ql.mem.write(buf, size*b"A")
    except unicorn.unicorn_py3.unicorn.UcError:
        crash(ql, hook_data.func_name)
        return
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

