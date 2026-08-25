from contextlib import contextmanager
from typing import Generator
from colorama import Fore, Style
from qiling import Qiling
from .params import MIN_PARAM_ADDR
import unicorn


@contextmanager
def mapped_memory_ctx(
    ql: Qiling,
    size: int,
    *,
    minaddr: int = MIN_PARAM_ADDR,
    perms: int = unicorn.UC_PROT_ALL,
    info: str = None,
) -> Generator[int, None, None]:
    """Context manager to map memory in Qiling for its duration."""
    addr = None
    try:
        addr = ql.mem.map_anywhere(
            size,
            minaddr=minaddr,
            perms=perms,
            info=info,
        )
        yield addr
    finally:
        if addr is not None:
            ql.mem.unmap(addr, size)


def _func_end_emu(ql: Qiling, fn_name: str) -> None:
    ql.log.info(
        "%s[%s] reach end @%#0x%s",
        Fore.BLUE,
        fn_name,
        ql.arch.regs.read("PC"),
        Style.RESET_ALL,
    )
    ql.stop()


@contextmanager
def stop_hooks_at(
    ql: Qiling,
    *addresses: int,
    user_data: str = None,
) -> Generator[None, None, None]:
    """Context manager to stop emulation at certain addresses."""
    hooks = []

    for address in addresses:
        hooks.append(ql.hook_address(_func_end_emu, address, user_data=user_data))
    try:
        yield
    finally:
        for hook in hooks:
            hook.remove()
