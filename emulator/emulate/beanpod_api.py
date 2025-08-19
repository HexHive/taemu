from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *


from Crypto.Random import get_random_bytes

from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from .gp_api import TEE_LogvPrintf

def ut_pf_log_msg(ql: Qiling, func_name):
    TEE_LogvPrintf(ql, func_name)

def mdrv_open(ql: Qiling, func_name):
    ql.os.fcall.cc.setReturnValue(0x123)
    ql.arch.regs.arch_pc = ql.arch.regs.lr