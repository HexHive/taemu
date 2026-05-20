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
        ["readelf", "-r","--use-dynamic", "--wide", ta_path.as_posix()]
    ).decode()
    plt_off = raw.find("'PLT' relocation section")
    plt = raw[plt_off:]
    plt_lines = plt.split("\n")
    plt_lines = plt_lines[2:]
    out: List[QseeReloc] = []
    for l in plt_lines:
        mtch = re.match(
            r"([0-9a-f]+) +([0-9a-f]+) +(R_AARCH64_JUMP_SLOT|[a-zA-Z_0-9]+) +([0-9a-f]{16}) +([a-zA-Z_]+) \+",
            l,
        )
        if not mtch:
            log.warning("qsee_read_relocs no match %s", l)
            continue
        offset_value = int(mtch.group(1), 16)
        r_type = mtch.group(3)
        if r_type != "R_AARCH64_JUMP_SLOT":
            log.warning("qsee_read_relocs non-jump-slot relocation type %s %s", r_type, l)
            continue
        symbol_value = int(mtch.group(4), 16)
        name = mtch.group(5)

        if symbol_value != 0:
            log.debug("qsee_read_relocs symbol-value non-zero %s %x", name, symbol_value)

        out.append(QseeReloc(name, offset_value, symbol_value, r_type))
    return out


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("ta_path", type=Path, nargs="+", help="Path to the QSEE TA ELF file")
    args = parser.parse_args()
    print("TA Name, Reloc Name, Reloc Offset, Reloc Symbol Value, Reloc Type, Reloc Addend", file=sys.stderr)
    for ta_path in args.ta_path:
        print(f"Reading relocations for {ta_path}", file=sys.stderr)
        for reloc in qsee_read_relocs(ta_path):
            print("%s %s %#016x %#016x %s %#016x" % (ta_path.name, reloc.name, reloc.offset, reloc.symbol_value, reloc.r_type, reloc.addend))
