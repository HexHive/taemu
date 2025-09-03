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

def TEES_GetIrsFlagValue(ql: Qiling, hook_data):
    ql.log.info(
        f'{hook_data.func_name} returning 0'
    )
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_IsREESharedMemory(ql: Qiling, hook_data):
    ql.log.info(
        f'{hook_data.func_name} returning 0'
    )
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def TEES_CheckSecureObjectCreator(ql: Qiling, hook_data):
    ql.log.info(
        f'{hook_data.func_name} returning 1'
    )
    ql.os.fcall.cc.setReturnValue(1)
    ql.arch.regs.arch_pc = ql.arch.regs.lr 

fd_counter = 5
fds = {}

def open(ql: Qiling, hook_data):
    global fds, fd_counter
    p = ql.os.resolve_fcall_params({"path": STRING,})
    path = p["path"]
    ql.log.info(
        f'{hook_data.func_name} called for {path} returning fd {fd_counter}'
    )
    ql.os.fcall.cc.setReturnValue(fd_counter) 
    fd_counter+=1
    fds[fd_counter] = path
    ql.arch.regs.arch_pc = ql.arch.regs.lr

def teegris_log_encrypt(ql: Qiling, hook_data):
    ql.os.fcall.cc.setReturnValue(0)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
