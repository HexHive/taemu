from qiling import Qiling
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from .common import CRASH_PC


def memory_alignment_round_up(addr, roundup):
    return addr - (addr % roundup) + roundup


ASAN_REDZONE_SIZE = 0x20
HOOKS = {}


def is_access_valid(ql, heap, address, size, func_name, is_write=False):
    access = "write" if is_write else "read"
    for redzone_start, redzone_size in heap["redzones"].items():
        if address > redzone_start and address < redzone_start + redzone_size:
            ql.log.critical(
                f"=================[lr: {ql.arch.regs.lr:#0x}] [{func_name}] out-of-bound {access} on address {address:#x}, size {size:#x}!!"
            )
            ql.arch.regs.arch_pc = CRASH_PC
            return False
        if address + size > redzone_start and address <= redzone_start:
            ql.log.critical(
                f"=================[lr: {ql.arch.regs.lr:#0x}] [{func_name}] out-of-bound {access} on address {address:#x}, size {size:#x}!!"
            )
            ql.arch.regs.arch_pc = CRASH_PC
            return False
    return True


def invalid_region_read(
    ql: Qiling, access: int, address: int, size: int, value: int
) -> None:
    # only read accesses are expected here
    assert access == UC_MEM_READ

    ql.log.critical(
        f"=================[lr: {ql.arch.regs.lr:#0x}]out-of-bound read on address {address:#x}, size {size:#x}!!"
    )
    ql.arch.regs.arch_pc = CRASH_PC
    # ql.emu_stop()


def invalid_region_write(
    ql: Qiling, access: int, address: int, size: int, value: int
) -> None:
    # only read accesses are expected here
    assert access == UC_MEM_WRITE

    ql.log.critical(
        f"=================[lr: {ql.arch.regs.lr:#0x}]out-of-bound write on address {address:#x}, size {size:#x}!!"
    )
    ql.arch.regs.arch_pc = CRASH_PC
    # ql.emu_stop()


def unmmaped_region_access(
    ql: Qiling, access: int, address: int, size: int, value: int
) -> None:

    ql.log.critical(
        f"=================[lr: {ql.arch.regs.lr:#0x}]uaf on address {address:#x}, size {size:#x}!!"
    )
    ql.arch.regs.arch_pc = CRASH_PC
    # ql.emu_stop()


def asan_hook_redzone_mem_rw(redzone, size, ql: Qiling):
    ql.log.debug(f"ASAN: hook rw for redzone [{redzone:#x}:{size+redzone:#x}]")
    rh = ql.hook_mem_read(invalid_region_read, begin=redzone, end=redzone + size - 1)
    wh = ql.hook_mem_write(invalid_region_write, begin=redzone, end=redzone + size - 1)
    HOOKS[redzone] = [rh, wh]


def asan_hook_free_mem_rw(freed_region, size, ql: Qiling):
    real_size = memory_alignment_round_up(size + 2 * ASAN_REDZONE_SIZE, 0x1000)
    # ql.hook_mem_unmapped(unmmaped_region_access, begin=freed_region, end=freed_region+real_size-1)
    redzone_before = freed_region
    redzone_after = freed_region + ASAN_REDZONE_SIZE + size
    rh, wh = HOOKS[redzone_before]
    ql.log.debug(
        f"ASAN: unhook rw for redzone [{redzone_before:#0x}:{redzone_before+ASAN_REDZONE_SIZE:#0x}]"
    )
    ql.hook_del(rh)
    ql.hook_del(wh)
    del HOOKS[redzone_before]
    rh, wh = HOOKS[redzone_after]
    ql.log.debug(
        f"ASAN: unhook rw for redzone [{redzone_after:#0x}:{redzone_before+real_size:#0x}]"
    )
    ql.hook_del(rh)
    ql.hook_del(wh)
    del HOOKS[redzone_after]
