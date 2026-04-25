from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from unicorn.arm_const import *
from .err import *
from ... import asan
from ...common import CRASH_PC, HEAP_MEM, crash
import unicorn


def memset_core(ql, hook_data, called_from_api_emu):
    func_name = hook_data.func_name
    emu = hook_data.emu
    params = ql.os.resolve_fcall_params({"dest": POINTER, "x": BYTE, "size": POINTER})
    ql.log.info(
        f'{func_name} {params["size"]:#0x} bytes of {hex(params["x"])} fill to {hex(params["dest"])}'
    )
    if not asan.is_access_valid(
        ql,
        hook_data.emu.HEAP,
        params["dest"],
        params["size"],
        hook_data.func_name,
        is_write=True,
    ):
        return
    try:
        ql.mem.write(params["dest"], params["size"] * params["x"].to_bytes(1, "little"))
    except unicorn.unicorn_py3.unicorn.UcError as e:
        crash(ql, func_name)
        return
    emu.writeback_shm(params["dest"], params["size"])

    if not called_from_api_emu:
        ql.arch.regs.arch_pc = ql.arch.regs.lr


def malloc_core(ql: Qiling, size, hook_data, called_from_api_emu):
    func_name = hook_data.func_name

    real_size = asan.memory_alignment_round_up(
        size + 2 * asan.ASAN_REDZONE_SIZE, 0x1000
    )

    out = ql.mem.map_anywhere(real_size, minaddr=HEAP_MEM, perms=3, info="malloc_chunk")
    ret2user_out = out + asan.ASAN_REDZONE_SIZE
    ql.log.info(f"{func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    hook_data.emu.HEAP["allocated"][ret2user_out] = size
    if ret2user_out in hook_data.emu.HEAP["freed"]:
        del hook_data.emu.HEAP["freed"][ret2user_out]

    ql.log.debug("redzone hook %#0x", out)
    asan.asan_hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE, ql)
    hook_data.emu.HEAP["redzones"][out] = asan.ASAN_REDZONE_SIZE
    ql.log.debug("redzone hook %#0x", ret2user_out + size)
    asan.asan_hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size, ql
    )
    hook_data.emu.HEAP["redzones"][ret2user_out + size] = (
        real_size - asan.ASAN_REDZONE_SIZE - size
    )

    if not called_from_api_emu:
        ql.os.fcall.cc.setReturnValue(ret2user_out)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return 
    else:
        return ret2user_out

def calloc_core(ql: Qiling, nmemb, size, hook_data, called_from_api_emu):
    size = nmemb * size 

    real_size = asan.memory_alignment_round_up(
        size + 2 * asan.ASAN_REDZONE_SIZE, 0x1000
    )

    out = ql.mem.map_anywhere(real_size, minaddr=HEAP_MEM, info="malloc_chunk")
    ret2user_out = out + asan.ASAN_REDZONE_SIZE

    ql.log.info(f"{hook_data.func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    hook_data.emu.HEAP["allocated"][ret2user_out] = size
    if ret2user_out in hook_data.emu.HEAP["freed"]:
        del hook_data.emu.HEAP["freed"][ret2user_out]

    asan.asan_hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE, ql)
    asan.asan_hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size, ql
    )
    hook_data.emu.HEAP["redzones"][out] = asan.ASAN_REDZONE_SIZE
    hook_data.emu.HEAP["redzones"][ret2user_out + size] = (
        real_size - asan.ASAN_REDZONE_SIZE - size
    )
    if not called_from_api_emu:
        ql.os.fcall.cc.setReturnValue(ret2user_out)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
    else:
        return ret2user_out


def free_core(ql: Qiling, ptr, hook_data, called_from_api_emu):
    func_name = hook_data.func_name
    if ptr == 0:
        if not called_from_api_emu:
            ql.arch.regs.arch_pc = ql.arch.regs.lr
        return
    if ptr not in hook_data.emu.HEAP["allocated"]:
        ql.log.critical(f"corrupted free at: {hex(ptr)}, {hook_data.emu.HEAP}")
        crash(ql, func_name)
        return
    size = hook_data.emu.HEAP["allocated"][ptr]
    if ptr in hook_data.emu.HEAP["freed"]:
        ql.log.critical(f"double free at: {hex(ptr)}, {hook_data.emu.HEAP}")
        crash(ql, func_name)
        return
    ql.log.info(f"{func_name}: freeing memory at {hex(ptr)}")
    real_ptr = ptr - asan.ASAN_REDZONE_SIZE
    if size == 0:
        ql.mem.unmap(real_ptr, (1 + 0x1000 - 1) & ~(0x1000 - 1))
    else:
        ql.mem.unmap(real_ptr, (size + 0x1000 - 1) & ~(0x1000 - 1))
    del hook_data.emu.HEAP["redzones"][real_ptr]
    del hook_data.emu.HEAP["redzones"][ptr + size]
    hook_data.emu.HEAP["freed"][ptr] = size
    del hook_data.emu.HEAP["allocated"][ptr]

    asan.asan_hook_free_mem_rw(real_ptr, size, ql)

    if not called_from_api_emu:
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
