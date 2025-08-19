from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from unicorn.arm_const import *
from .err import *

HEAP = {"allocated": {}, "freed": {}}

HEAP_MEM=0xaaaaa000

def memset_core(ql, func_name, called_from_custom_lib):
    params = ql.os.resolve_fcall_params({"dest": INT, "x": BYTE, "size": INT})
    ql.log.info(
        f'{func_name} {params["size"]:#0x} bytes of {hex(params["x"])} fill to {hex(params["dest"])}'
    )
    if not called_from_custom_lib:
        ql.arch.regs.arch_pc = ql.arch.regs.lr

def malloc_core(ql: Qiling, func_name, called_from_custom_lib):
    size = ql.os.resolve_fcall_params({"size": INT})["size"]
    ret2user_out = ql.mem.map_anywhere(size, minaddr=HEAP_MEM, perms=3, info="malloc_chunk")
    ql.log.info(f"{func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    HEAP["allocated"][ret2user_out] = size
    if ret2user_out in HEAP["freed"]:
        del HEAP["freed"][ret2user_out]
    ql.os.fcall.cc.setReturnValue(ret2user_out)
    if not called_from_custom_lib:
        ql.arch.regs.arch_pc = ql.arch.regs.lr


def calloc_core(ql:Qiling, func_name):
    param = ql.os.resolve_fcall_params({"nmemb": INT, "size": INT})
    size = param['size'] * param['nmemb']
    ret2user_out = ql.mem.map_anywhere(size, minaddr=HEAP_MEM, info="malloc_chunk")
    ql.log.info(f"{func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    HEAP["allocated"][ret2user_out] = size
    if ret2user_out in HEAP["freed"]:
        del HEAP["freed"][ret2user_out]
    ql.os.fcall.cc.setReturnValue(ret2user_out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def free_core(ql:Qiling, func_name, called_from_custom_lib):
    ptr = ql.os.resolve_fcall_params({"ptr": INT})["ptr"]
    if ptr not in HEAP["allocated"]:
        ql.log.critical(f"corrupted free at: {hex(ptr)}, {HEAP}")
        ql.arch.regs.arch_pc = 0xdeadbeef
    size = HEAP["allocated"][ptr]
    if ptr in HEAP["freed"]:
        ql.log.critical(f"double free at: {hex(ptr)}, {HEAP}")
        ql.arch.regs.arch_pc = 0x0
    ql.log.info(f"{func_name}: freeing memory at {hex(ptr)}")
    ql.mem.unmap(ptr, (size + 0x1000 - 1) & ~(0x1000 - 1))
    HEAP["freed"][ptr] = size
    del HEAP["allocated"][ptr]
    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    if not called_from_custom_lib:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
