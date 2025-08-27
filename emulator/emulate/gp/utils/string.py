from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from unicorn.arm_const import *
from .err import *
from ... import asan

HEAP = {"allocated": {}, "freed": {}}

HEAP_MEM=0xaaaaa000

def memset_core(ql, hook_data, called_from_custom_lib):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"dest": POINTER, "x": BYTE, "size": POINTER})
    ql.log.info(
        f'{func_name} {params["size"]:#0x} bytes of {hex(params["x"])} fill to {hex(params["dest"])}'
    )
    if not called_from_custom_lib:
        ql.arch.regs.arch_pc = ql.arch.regs.lr

def malloc_core(ql: Qiling, hook_data, called_from_custom_lib):
    func_name = hook_data.func_name
    size = ql.os.resolve_fcall_params({"size": INT})["size"]

    real_size = asan.memory_alignment_round_up(
        size + 2 * asan.ASAN_REDZONE_SIZE, 0x1000
    )

    out = ql.mem.map_anywhere(real_size, minaddr=HEAP_MEM, perms=3, info="malloc_chunk")
    ret2user_out = out + asan.ASAN_REDZONE_SIZE
    ql.log.info(f"{func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    HEAP["allocated"][ret2user_out] = size
    if ret2user_out in HEAP["freed"]:
        del HEAP["freed"][ret2user_out]

    ql.log.info(f'redzone hook {hex(out)}')
    asan.asan_hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE, ql)
    ql.log.info(f'redzone hook {hex(ret2user_out + size)}')
    asan.asan_hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size, ql
    )

    ql.os.fcall.cc.setReturnValue(ret2user_out)
    if not called_from_custom_lib:
        ql.arch.regs.arch_pc = ql.arch.regs.lr



def calloc_core(ql:Qiling, hook_data):
    param = ql.os.resolve_fcall_params({"nmemb": INT, "size": INT})
    size = param['size'] * param['nmemb']

    real_size = asan.memory_alignment_round_up(
        size + 2 * asan.ASAN_REDZONE_SIZE, 0x1000
    )

    out = ql.mem.map_anywhere(real_size, minaddr=HEAP_MEM, info="malloc_chunk")
    ret2user_out = out + asan.ASAN_REDZONE_SIZE

    ql.log.info(f"{func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    HEAP["allocated"][ret2user_out] = size
    if ret2user_out in HEAP["freed"]:
        del HEAP["freed"][ret2user_out]

    asan.asan_hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE, ql)
    asan.asan_hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size, ql
    )

    ql.os.fcall.cc.setReturnValue(ret2user_out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr


def free_core(ql:Qiling, hook_data, called_from_custom_lib):
    func_name = hook_data.func_name
    ptr = ql.os.resolve_fcall_params({"ptr": INT})["ptr"]
    if ptr not in HEAP["allocated"]:
        ql.log.critical(f"corrupted free at: {hex(ptr)}, {HEAP}")
        ql.arch.regs.arch_pc = 0xdeadbeef
        return
    size = HEAP["allocated"][ptr]
    if ptr in HEAP["freed"]:
        ql.log.critical(f"double free at: {hex(ptr)}, {HEAP}")
        ql.arch.regs.arch_pc = 0xdeadbeef
        return
    ql.log.info(f"{func_name}: freeing memory at {hex(ptr)}")
    real_ptr = ptr - asan.ASAN_REDZONE_SIZE
    ql.mem.unmap(real_ptr, (size + 0x1000 - 1) & ~(0x1000 - 1))
    HEAP["freed"][ptr] = size
    del HEAP["allocated"][ptr]

    asan.asan_hook_free_mem_rw(real_ptr, size, ql)

    ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
    if not called_from_custom_lib:
        ql.arch.regs.arch_pc = ql.arch.regs.lr
