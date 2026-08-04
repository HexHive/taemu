from .fuzz_record import Record, Status
from .qiling_extend import QilingExtend as Qiling
from colorama import Fore, Back, Style
from typing import Any, Callable, Optional, List, Dict

CRASH_PC = 0xDEADBEEF
CRASH_PC_2 = 0xDEADBEEE
NOTIMPL_PC = 0xCAFECAFE
HEAP_MEM = 0xAAAAA000

def have_overlaps(records: List[Record]) -> bool:
    # sweep line algorithm to check for duplicates
    if len(records) <= 1:
        return False

    lines = []
    for idx, record in enumerate(records):
        if record.size is None:
            print(
                f"Warning: record {record.addr} has no size, which thus we treat it as a single byte"
            )
            lines.append((record.addr, record.addr + 1, idx))
        else:
            print(f"[{__name__}] Adding record: {hex(record.addr)} - {hex(record.addr + record.size)}")
            lines.append((record.addr, record.addr + record.size, idx))
    
    overlap_found = False
    lines.sort(key=lambda x: x[0])
    max_end = lines[0][1]
    for start, end, idx in lines[1:]:
        # check section like [a, b) and [b, c) for non-overlaps (b is not included)
        if start < max_end:
            overlap_found = True
            records[idx].is_second_fetch = True

        max_end = max(max_end, end)
    return overlap_found

def finalize_fuzzing(ql: Qiling, user_data: Any) -> None:
    ql.log.info(
        Fore.BLUE
        + f"[+] [{user_data}] Finished one fuzzing input at @{ql.arch.regs.read('PC'):#0x}"
        + Style.RESET_ALL
    )
    ql.emu.save_records_to_queue(checker=lambda records: have_overlaps(records))

def crash(ql, func_name):
    ql.log.critical(
        f"=================[lr: {ql.arch.regs.lr:#0x}] [{func_name}] memory corruption detected!!"
    )
    ql.arch.regs.arch_pc = CRASH_PC


def crash_notimpl(ql, msg):
    ql.log.critical(f"=================[lr: {ql.arch.regs.lr:#0x}] {msg}")
    ql.arch.regs.arch_pc = NOTIMPL_PC
