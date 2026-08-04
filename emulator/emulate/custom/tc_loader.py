from qiling import Qiling
from elftools.elf.elffile import ELFFile
import subprocess
import re

_GLOBAL_OFFSET_TABLE_ = 0x0
text_base = 0x3014
ro_base = 0x2000


def tc_read_relcall(ta_path):
    # 000007d0  0000861c R_ARM_CALL             00000000   TEE_SyncPersistentObject
    out = []
    raw = subprocess.check_output(f"readelf -r  --wide {ta_path}", shell=True).decode()
    lines = raw.split("\n")
    for l in lines:
        mtch = re.match(
            r"([0-9a-z]+) +([0-9a-z]+) +R_ARM_CALL +00000000 +([a-zA-Z_]+)", l
        )
        if not mtch:
            continue
        out.append((mtch.group(3), int(mtch.group(1), 16) + text_base))
    return out


def tc_load(ql: Qiling, ta_path):
    if "7461736b5f73746f72616765" in ta_path:
        # load task storage
        ql.mem.map(ro_base, 0x4000, info=ta_path)
        ql.mem.map(_GLOBAL_OFFSET_TABLE_, 0x1000, info="_GLOBAL_OFFSET_TABLE_")
        with open(ta_path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                name = section.name
                addr = section["sh_addr"]  # section virtual address
                size = section["sh_size"]
                print(f"{name:15} @ 0x{addr:x}, size={size}")
                if name == ".text":
                    ql.mem.write(0x3014, section.data())
                if name == ".rodata":
                    ql.mem.write(ro_base, section.data())
                if name == ".data":
                    ql.mem.write(0x3000, section.data())
                if name == ".bss":
                    ql.mem.write(0x3008, section.data())
        raw = subprocess.check_output(
            f"readelf -r  --wide {ta_path}", shell=True
        ).decode()
        lines = raw.split("\n")
        for l in lines:
            if "_GLOBAL_OFFSET_TABLE_" in l:
                addr = int(l.split(" ")[0], 16)
                # print(f'glob offset writing to {hex(text_base + addr)}: {hex(_GLOBAL_OFFSET_TABLE_)}')
                # ql.mem.write_ptr(text_base + addr, _GLOBAL_OFFSET_TABLE_)
        for l in lines:
            mtch = re.match(r"([0-9a-z]+) +([0-9a-z]+) +R_ARM_REL32 +([0-9a-z]+)", l)
            if not mtch:
                continue
            off = int(mtch.group(1), 16) + text_base
            data_off = int(mtch.group(3), 16) + ro_base
            # ql.mem.write_ptr(off, data_off)
        ql.mem.write(0x4138, b"\xe8\xe9\xff\xff")
