from qiling import Qiling
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from .common import CRASH_PC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ta_mgr import TAEMU

def memory_alignment_round_up(addr, roundup):
    return addr - (addr % roundup) + roundup


ASAN_REDZONE_SIZE = 0x20


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

class Asan:
    def __init__(self, emu: 'TAEMU'):
        self.emu = emu
        self.HOOKS = {}

    def save(self):
        return {
            "REDZONES": {
                redzone: size
                for redzone, (_, _, size) in self.HOOKS.items()
            }
        }
    
    def restore(self, state: dict):
        self._unhook_all()
        for redzone, size in state["REDZONES"].items():
            self.hook_redzone_mem_rw(redzone, size)

    def _unhook_all(self):
        ql: Qiling = self.emu.ql
        # first load, so we don't change the dictionary while iterating over it
        L = list(self.HOOKS.items())
        for redzone, hook_data in L:
            rh, wh, _ = hook_data
            ql.hook_del(rh)
            ql.hook_del(wh)
            del self.HOOKS[redzone]

    def is_access_valid(self, heap, address, size, func_name, is_write=False):
        ql: Qiling = self.emu.ql
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


    def hook_redzone_mem_rw(self, redzone, size):
        ql: Qiling = self.emu.ql
        ql.log.debug(f"ASAN: hook rw for redzone [{redzone:#x}:{size+redzone:#x}]")

        rh = ql.hook_mem_read(invalid_region_read, begin=redzone, end=redzone + size - 1)
        wh = ql.hook_mem_write(invalid_region_write, begin=redzone, end=redzone + size - 1)
        self.HOOKS[redzone] = [rh, wh, size]


    def hook_free_mem_rw(self, freed_region, size):
        ql: Qiling = self.emu.ql
        real_size = memory_alignment_round_up(size + 2 * ASAN_REDZONE_SIZE, 0x1000)
                
        # ql.hook_mem_unmapped(unmmaped_region_access, begin=freed_region, end=freed_region+real_size-1)
        redzone_before = freed_region
        redzone_after = freed_region + ASAN_REDZONE_SIZE + size
        rh, wh, _ = self.HOOKS[redzone_before]
        ql.log.debug(
            f"ASAN: unhook rw for redzone [{redzone_before:#0x}:{redzone_before+ASAN_REDZONE_SIZE:#0x}]"
        )
        ql.hook_del(rh)
        ql.hook_del(wh)
        del self.HOOKS[redzone_before]
        
        rh, wh, _ = self.HOOKS[redzone_after]
        ql.log.debug(
            f"ASAN: unhook rw for redzone [{redzone_after:#0x}:{redzone_before+real_size:#0x}]"
        )
        ql.hook_del(rh)
        ql.hook_del(wh)
        del self.HOOKS[redzone_after]

def asan_hook_redzone_mem_rw(redzone, size, ql: Qiling):
    """Module-level entry point for callers that only hold a `ql`.

    asan.py is class-based here (Asan.HOOKS lives on the emulator instance), but
    the redzoned allocator in gp/utils/string.py and the uefi harnesses call this
    free function. Delegate to the instance so there is a single hook registry
    that remove_param_redzones / Asan._unhook_all can actually tear down.
    """
    inst = getattr(getattr(ql, "emu", None), "asan", None)
    if inst is None:
        ql.log.warning("ASAN: no Asan instance on ql.emu; redzone hooks not installed")
        return
    inst.hook_redzone_mem_rw(redzone, size)


def install_param_redzones(ql, emu, data, size, minaddr):
    """Map a redzoned region for a TEE_Param memref buffer:
    [redzone_before][ data (size) ][redzone_after ... page end].

    The REE param buffers (params.py) were page-mapped with no redzone, so OOB
    *writes* to a response buffer (HDCP cmd-0x94) and OOB *reads* of a request
    buffer (duldar setup-pw, SEMeSE off-by-8) executed silently. Wrapping them
    like the heap allocator does makes those trip a hardware mem hook ->
    CRASH_PC; registering in emu.HEAP['redzones'] also lets the software
    is_access_valid() path (hooked memcpy/strcpy/TEE_MemMove) catch them.

    Returns (user_ptr, region_base, real_size)."""
    real_size = memory_alignment_round_up(size + 2 * ASAN_REDZONE_SIZE, 0x1000)
    region = ql.mem.map_anywhere(real_size, minaddr=minaddr, perms=3, info="shared_redzoned_param")
    user = region + ASAN_REDZONE_SIZE
    if data:
        ql.mem.write(user, bytes(data[:size]))
    after = user + size
    after_size = real_size - ASAN_REDZONE_SIZE - size
    if emu is not None:
        # asan.py is class-based here (Asan.HOOKS), so the redzone hooks are
        # registered on the instance rather than a module-level HOOKS dict.
        emu.asan.hook_redzone_mem_rw(region, ASAN_REDZONE_SIZE)
        emu.asan.hook_redzone_mem_rw(after, after_size)  # same registry as the shim
        emu.HEAP["redzones"][region] = ASAN_REDZONE_SIZE
        emu.HEAP["redzones"][after] = after_size
    return user, region, real_size


def remove_param_redzones(ql, emu, region, size, real_size):
    """Tear down a region created by install_param_redzones: drop the hardware
    hooks and de-register the zones. We deliberately do NOT unmap the region:
    under AFL the forkserver resets memory every iteration, and an interactive
    PoC sends only a handful of commands (<=4 memrefs each), so leaving the page
    mapped costs nothing -- whereas unmapping it lets the next command's
    map_anywhere reuse the same address while a previous command's
    (never-removed) shared-memory sync hooks still point there, which faulted
    multi-command PoCs (UC_ERR_WRITE_UNMAPPED)."""
    after = region + ASAN_REDZONE_SIZE + size
    for start in (region, after):
        if emu is None:
            continue
        # Asan.HOOKS entries are [read_hook, write_hook, size]
        hooks = emu.asan.HOOKS.pop(start, None)
        if hooks:
            for h in hooks[:2]:
                try:
                    ql.hook_del(h)
                except Exception:
                    pass
        emu.HEAP["redzones"].pop(start, None)
