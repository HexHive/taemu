from qiling import Qiling
from qiling.os.const import STRING, INT, BYTE, POINTER
from unicorn.arm_const import *
from .err import *
from ... import asan
from ...common import CRASH_PC, HEAP_MEM, crash
import unicorn
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...emulator_no_loader import HookData

import os

# --- weaponization mode ------------------------------------------------------
# TAEMU_WEAPONIZE lays heap allocations ADJACENTLY with no redzones / guard
# pages, like a real allocator, so an overflow asan already detected can be
# developed into an actual overwrite-the-next-object primitive for exploit dev.
# It is the opposite of the asan detector (which page-isolates every chunk):
# use it to *weaponize* a known bug, not to find bugs. Param redzones are also
# suppressed in this mode (see params.py). Cheap wild-free / double-free checks
# are kept (they need no redzone).
WEAPONIZE = "TAEMU_WEAPONIZE" in os.environ
_WEAPON_ALIGN = 16
_WEAPON_ARENA = 0x400000  # 4 MiB contiguous arena


def _weapon_alloc(ql, emu, size):
    """Bump-allocate `size` bytes contiguously from a per-emu arena (no redzone,
    no guard page) so adjacent allocations actually neighbour each other."""
    arena = getattr(emu, "WEAPON_HEAP", None)
    if arena is None:
        base = ql.mem.map_anywhere(_WEAPON_ARENA, minaddr=HEAP_MEM, perms=3, info="weapon_heap")
        arena = {"base": base, "brk": base, "end": base + _WEAPON_ARENA}
        emu.WEAPON_HEAP = arena
    n = (size + _WEAPON_ALIGN - 1) & ~(_WEAPON_ALIGN - 1)
    if n == 0:
        n = _WEAPON_ALIGN
    if arena["brk"] + n > arena["end"]:  # arena exhausted: fall back to a fresh map
        return ql.mem.map_anywhere(max(n, 0x1000), minaddr=HEAP_MEM, perms=3, info="weapon_of")
    ptr = arena["brk"]
    arena["brk"] += n
    return ptr


def _weapon_return(ql, hook_data, size, called_from_custom_lib):
    ptr = _weapon_alloc(ql, hook_data.emu, size)
    hook_data.emu.HEAP["allocated"][ptr] = size
    hook_data.emu.HEAP["freed"].pop(ptr, None)
    ql.log.info(f"{hook_data.func_name}: [weaponize] {hex(size)} @ {hex(ptr)} (adjacent, no redzone)")
    ql.os.fcall.cc.setReturnValue(ptr)
    if not called_from_custom_lib:
        ql.arch.regs.arch_pc = ql.arch.regs.lr

def memset_core(ql, hook_data, called_from_api_emu):
    func_name = hook_data.func_name
    emu = hook_data.emu
    params = ql.os.resolve_fcall_params({"dest": POINTER, "x": BYTE, "size": POINTER})
    ql.log.info(
        f'{func_name} {params["size"]:#0x} bytes of {hex(params["x"])} fill to {hex(params["dest"])}'
    )
    if not hook_data.emu.asan.is_access_valid(
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


def malloc_core(ql: Qiling, size, hook_data: 'HookData', called_from_api_emu):
    func_name = hook_data.func_name

    if WEAPONIZE:
        _weapon_return(ql, hook_data, size, called_from_api_emu)
        return

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
    hook_data.emu.asan.hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE)
    hook_data.emu.HEAP["redzones"][out] = asan.ASAN_REDZONE_SIZE
    ql.log.debug("redzone hook %#0x", ret2user_out + size)
    hook_data.emu.asan.hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size
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

def calloc_core(ql: Qiling, nmemb, size, hook_data: 'HookData', called_from_api_emu):
    size = nmemb * size 

    if WEAPONIZE:
        _weapon_return(ql, hook_data, size, False)
        return

    real_size = asan.memory_alignment_round_up(
        size + 2 * asan.ASAN_REDZONE_SIZE, 0x1000
    )

    out = ql.mem.map_anywhere(real_size, minaddr=HEAP_MEM, info="malloc_chunk")
    ret2user_out = out + asan.ASAN_REDZONE_SIZE

    ql.log.info(f"{hook_data.func_name}: allocated {hex(size)} at {hex(ret2user_out)}")
    hook_data.emu.HEAP["allocated"][ret2user_out] = size
    if ret2user_out in hook_data.emu.HEAP["freed"]:
        del hook_data.emu.HEAP["freed"][ret2user_out]

    hook_data.emu.asan.hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE)
    hook_data.emu.asan.hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size
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


def free_core(ql: Qiling, ptr, hook_data: 'HookData', called_from_api_emu):
    func_name = hook_data.func_name
    if ptr == 0:
        if not called_from_api_emu:
            ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

    if WEAPONIZE:
        # adjacency mode: no per-chunk page/redzone to tear down. Keep wild-free
        # and double-free detection (cheap); mark freed and leave the memory
        # mapped so UAF reads still resolve to stale contents.
        if ptr not in hook_data.emu.HEAP["allocated"]:
            ql.log.critical(f"corrupted free at: {hex(ptr)}")
            crash(ql, func_name)
            return
        if ptr in hook_data.emu.HEAP["freed"]:
            ql.log.critical(f"double free at: {hex(ptr)}")
            crash(ql, func_name)
            return
        hook_data.emu.HEAP["freed"][ptr] = hook_data.emu.HEAP["allocated"][ptr]
        del hook_data.emu.HEAP["allocated"][ptr]
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
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

    hook_data.emu.asan.hook_free_mem_rw(real_ptr, size)

    if not called_from_api_emu:
        ql.os.fcall.cc.setReturnValue(TEE_SUCCESS)
        ql.arch.regs.arch_pc = ql.arch.regs.lr


def realloc_core(ql: Qiling, hook_data):
    func_name = hook_data.func_name
    params = ql.os.resolve_fcall_params({"ptr": INT, "size": INT})
    old_ptr = params["ptr"]
    size = params["size"]

    if WEAPONIZE:
        # adjacency realloc: bump-allocate a fresh block, copy old bytes over,
        # leak the old (same rationale as below). No redzones.
        new_ptr = _weapon_alloc(ql, hook_data.emu, size)
        old_size = hook_data.emu.HEAP["allocated"].get(old_ptr, 0) if old_ptr else 0
        if old_ptr and old_size:
            try:
                ql.mem.write(new_ptr, bytes(ql.mem.read(old_ptr, min(size, old_size))))
            except unicorn.unicorn_py3.unicorn.UcError:
                pass
        hook_data.emu.HEAP["allocated"][new_ptr] = size
        ql.os.fcall.cc.setReturnValue(new_ptr)
        ql.arch.regs.arch_pc = ql.arch.regs.lr
        return

    # Allocate a fresh redzoned block (mirrors malloc_core), copy the old
    # contents, and LEAK the old block. We deliberately do not free the old
    # allocation: free_core resolves its own register params and toggles
    # pc/return, which would corrupt this call frame's bookkeeping. Leaking is
    # harmless under emulation and keeps the asan redzone map consistent.
    real_size = asan.memory_alignment_round_up(
        size + 2 * asan.ASAN_REDZONE_SIZE, 0x1000
    )
    out = ql.mem.map_anywhere(real_size, minaddr=HEAP_MEM, perms=3, info="realloc_chunk")
    ret2user_out = out + asan.ASAN_REDZONE_SIZE
    ql.log.info(f"{func_name}: realloc {hex(old_ptr)} -> allocated {hex(size)} at {hex(ret2user_out)}")
    hook_data.emu.HEAP["allocated"][ret2user_out] = size
    if ret2user_out in hook_data.emu.HEAP["freed"]:
        del hook_data.emu.HEAP["freed"][ret2user_out]

    asan.asan_hook_redzone_mem_rw(out, asan.ASAN_REDZONE_SIZE, ql)
    hook_data.emu.HEAP["redzones"][out] = asan.ASAN_REDZONE_SIZE
    asan.asan_hook_redzone_mem_rw(
        ret2user_out + size, real_size - asan.ASAN_REDZONE_SIZE - size, ql
    )
    hook_data.emu.HEAP["redzones"][ret2user_out + size] = real_size - asan.ASAN_REDZONE_SIZE - size

    if old_ptr != 0 and old_ptr in hook_data.emu.HEAP["allocated"]:
        old_size = hook_data.emu.HEAP["allocated"][old_ptr]
        copy_size = min(old_size, size)
        if copy_size > 0:
            try:
                data = ql.mem.read(old_ptr, copy_size)
                ql.mem.write(ret2user_out, bytes(data))
            except unicorn.unicorn_py3.unicorn.UcError:
                crash(ql, func_name)
                return

    ql.os.fcall.cc.setReturnValue(ret2user_out)
    ql.arch.regs.arch_pc = ql.arch.regs.lr
