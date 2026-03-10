from elftools.elf.elffile import ELFFile
import sys
from elftools.elf.relocation import RelocationSection


def emulate_loader(filename):
    with open(filename, "rb") as f:
        elf = ELFFile(f)

        # Symbol table for lookups
        dynsym = elf.get_section_by_name(".dynsym")

        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            print(f"[+] Processing relocation section: {section.name}")

            for rel in section.iter_relocations():
                print(rel.entry)
                reloc_addr = rel.entry["r_offset"]
                r_type = rel.entry["r_info_type"]
                addend = rel.entry.get("r_addend", None)
                print(
                    f"  relocation at 0x{reloc_addr:x}, type={r_type}, addend={addend}"
                )


emulate_loader(sys.argv[1])
