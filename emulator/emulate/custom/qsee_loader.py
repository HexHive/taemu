from dataclasses import dataclass
import subprocess
import sys
import re
from pathlib import Path
import logging
from typing import List

from elftools.elf.dynamic import Dynamic, DynamicSegment
from elftools.elf.relocation import RelocationSection
from pwnlib.elf import ELF
from elftools.elf.elffile import ELFFile
from qiling import Qiling
from qiling.core import QL_ARCH, QL_OS
from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
log = logging.getLogger(__name__)

@dataclass
class QseeReloc:
    name: str
    offset: int
    symbol_value: int
    r_type: str
    addend: int = 0

    def __repr__(self):
        return f"QseeReloc('{self.name}', {(self.offset):#016x}, {(self.symbol_value):#016x}, {(self.addend):#016x})"

def qsee_read_relocs(ta_path: Path) -> List[QseeReloc]:
    raw = subprocess.check_output(
        f"readelf -r --use-dynamic --wide {ta_path}", shell=True
    ).decode()
    plt_off = raw.find("'PLT' relocation section")
    plt = raw[plt_off:]
    plt_lines = plt.split("\n")
    plt_lines = plt_lines[2:]
    out: List[QseeReloc] = []
    for l in plt_lines:
        mtch = re.match(
            r"([0-9a-f]+) +([0-9a-f]+) +(R_AARCH64_JUMP_SLOT) +([0-9a-f]{16}) +([a-zA-Z_]+) \+",
            l,
        )
        if not mtch:
            continue
        offset_value = int(mtch.group(1), 16)
        r_type = mtch.group(3)
        symbol_value = int(mtch.group(4), 16)
        name = mtch.group(5)

        if symbol_value != 0:
            log.debug("qsee_read_relocs symbol-value non-zero %s %x", name, symbol_value)
            # continue
        out.append(QseeReloc(name, offset_value, symbol_value, r_type))
    return out

def _format_map_info(map_info: List[tuple[int, int, str, str, str]]) -> str:
    return "\n".join([f"\t{start:#016x} {end:#016x} {perm} {name} {_}" for start, end, perm, name, _ in map_info])

def load_so_and_symbols(ql:Qiling, so_path: Path, so_base: int):
    ql.log.info("[+] Loading %s to %#0x", so_path.name, so_base)
    so_name = so_path.name
    ql2 = Qiling(
        [so_path.resolve().as_posix()],
        rootfs=so_path.parent,
        ostype=QL_OS.LINUX,
        archtype=QL_ARCH.ARM64,
    )
    curr_base = so_base
    orig_base = None
    for entry in ql2.mem.get_mapinfo():
        start, end, perm, name, _ = entry
        size = end - start
        if name != so_name:
            continue
        if orig_base is None:
            orig_base = start
        if perm == 'r-x':
            perm = UC_PROT_READ | UC_PROT_EXEC
        else:
            perm = UC_PROT_READ | UC_PROT_WRITE
        offset = start - orig_base
        ql.mem.map(curr_base + offset, size, perm, name)
        lib_mem=bytes(ql2.mem.read(start, size))
        ql.mem.write(curr_base + offset, lib_mem)
    print(_format_map_info(ql.mem.get_mapinfo()))

    symbols = {}
    with so_path.open("rb") as f:
        elf = ELFFile(f)
        elf.address = so_base
        for seg in elf.iter_segments():
            if not isinstance(seg, DynamicSegment):
                continue
            for sym in seg.iter_symbols():
                symbols[sym.name] = sym.entry["st_value"]
    return symbols


def read_got_entries(ql: Qiling, elf_path: Path, elf_base: int):
    symbols = {}
    with elf_path.open("rb") as f:
        elf = ELFFile(f)
        elf.address = elf_base
        for seg in elf.iter_segments():
            if not isinstance(seg, DynamicSegment):
                continue
            for sym in seg.iter_symbols():
                symbols[sym.name] = sym.entry["st_value"]
    return symbols


from unicorn import UC_PROT_READ, UC_PROT_WRITE
from unicorn.arm64_const import UC_ARM64_REG_TPIDRRO_EL0

PAGE = 0x1000
TLS_BASE = 0x73000000   # pick any free page-aligned address in your layout
TLS_SIZE = PAGE

def install_fake_tpidrro(ql):
    print(f"{ql.arch.regs.register_mapping=}")
    ql.mem.map(TLS_BASE, TLS_SIZE, perms=UC_PROT_READ | UC_PROT_WRITE, info="[fake_tpidrro]")
    ql.mem.write(TLS_BASE, b"\x00" * TLS_SIZE)

    # check exact name with ql.arch.regs.register_mapping() if needed
    ql.uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, TLS_BASE)

    # optional seed values
    # ql.mem.write(TLS_BASE + 4, b"\x00")
    def log_tls_read(ql, access, address, size, value):
        ql.log.debug("[tls-read]  addr=%#016x size=%#016x", address, size)

    def log_tls_write(ql, access, address, size, value):
        ql.log.debug("[tls-write] addr=%#016x size=%#016x value=%#016x", address, size, value)

    ql.hook_mem_read(log_tls_read, begin=TLS_BASE, end=TLS_BASE + TLS_SIZE - 1)
    ql.hook_mem_write(log_tls_write, begin=TLS_BASE, end=TLS_BASE + TLS_SIZE - 1)
    ql.log.info("[qsee] tpidrro_el0=%#016x", ql.uc.reg_read(UC_ARM64_REG_TPIDRRO_EL0))



LIBRARY_BASE = 0x70000000 # 0x555555400000
LIBRARY = "libcmnlib.so"
def qsee_fix_got(ql: Qiling, ta_path: Path, ta_elf: ELF, ql_resolve_mem: int):
    return qsee_read_relocs(ta_path)
    # This used to allocate the library memory, but now we just treat all the rellocs as not-in-the-so
    library_path = ta_path.with_name("lib64") / LIBRARY
    so_symbols = load_so_and_symbols(ql, library_path, LIBRARY_BASE)
    
    install_fake_tpidrro(ql)

    # This we will hook with our custom implemented functions
    leftover = []
    for qsee_reloc in qsee_read_relocs(ta_path):
        funcname = qsee_reloc.name
        off = qsee_reloc.offset
        sym = qsee_reloc.symbol_value
        
        if funcname in  so_symbols:
            so_loc = so_symbols[funcname] + LIBRARY_BASE
            ql.mem.write(
                ta_elf.address + off,
                (so_loc).to_bytes(ql.arch.pointersize, "little"),
            )
            ql.log.info(
                f"[qsee] hooking plt relocation function .so library function {funcname}, {hex(off)}, {hex(so_loc)}"
            )
        else:
            leftover.append(qsee_reloc)
    return leftover

if __name__ == "__main__":
    data = qsee_read_relocs(sys.argv[1])
    for reloc in data:
        print(reloc)
