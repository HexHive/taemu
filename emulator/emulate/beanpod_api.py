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

def ut_pf_log_msg(ql: Qiling, hook_data):
    TEE_LogvPrintf(ql, hook_data)

def mdrv_open(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0x123)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def msee_ta_printf_va(ql: Qiling, hook_data):
    TEE_LogPrintf(ql, hook_data)