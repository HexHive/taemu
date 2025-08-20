from enum import Enum
from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from .gp.utils.param import TEE_Param_Memref
from .gp.utils.err import *
from .gp.utils.string import *


from Crypto.Random import get_random_bytes

from .custom import rpmb
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from .gp_api import TEE_LogvPrintf, TEE_LogPrintf

def TEES_GetIrsFlagValue(ql: Qiling, func_name):
    ql.log.info(
        f'{func_name} returning 0'
    )
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr