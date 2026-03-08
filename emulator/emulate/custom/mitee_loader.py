import subprocess
import sys
import re
from pathlib import Path
def qsee_read_relocs(ta_path:Path):
    raw = subprocess.check_output(
        f"readelf -r --use-dynamic --wide {ta_path}", shell=True
    ).decode()
    plt_off = raw.find("'PLT' relocation section")
    plt = raw[plt_off:]
    plt_lines = plt.split("\n")
    plt_lines = plt_lines[2:]
    out = []
    for l in plt_lines:
        mtch = re.match(
            r"([0-9a-z]+) +([0-9a-z]+) +R_AARCH64_JUMP_SLOT +0000000000000000 +([a-zA-Z_]+) \+",
            l,
        )
        if not mtch:
            continue
        out.append((mtch.group(3), int(mtch.group(1), 16)))
    return out


def mitee_read_relocs(ta_path:Path):
    raw = subprocess.check_output(
        f"readelf -r --use-dynamic --wide {ta_path}", shell=True
    ).decode()
    plt_off = raw.find("'PLT' relocation section")
    relr_off = raw.find("'RELR' relocation section")
    rela_off = raw.find("'RELA' relocation section")
    plt = raw[plt_off:]
    relr = raw[relr_off:plt_off]
    rela = raw[rela_off:relr_off]
    plt_lines = plt.split("\n")
    plt_lines = plt_lines[2:]
    out = []
    for l in plt_lines:
        mtch = re.match(
            r"([0-9a-z]+) +([0-9a-z]+) +R_AARCH64_JUMP_SLOT +0000000000000000 +([a-zA-Z_]+) \+",
            l,
        )
        if not mtch:
            continue
        out.append((mtch.group(3), int(mtch.group(1), 16)))
    rela_lines = rela.split("\n")
    rela_lines = rela_lines[2:]
    for l in rela_lines:
        mtch = re.match(
            r"([0-9a-z]+) +([0-9a-z]+) +(R_AARCH64_GLOB_DAT|R_AARCH64_ABS64) +0000000000000000 +([a-zA-Z_]+) \+",
            l,
        )
        if not mtch:
            continue
        out.append((mtch.group(3), int(mtch.group(1), 16)))
    return out


def mitee_relr_relocs(ta_path):
    raw = subprocess.check_output(
        f"readelf -r --use-dynamic --wide {ta_path}", shell=True
    ).decode()
    plt_off = raw.find("'PLT' relocation section")
    relr_off = raw.find("'RELR' relocation section")
    relr = raw[relr_off:plt_off]
    relr_lines = relr.split("\n")
    relr_lines = relr_lines[2:]
    out = []
    for l in relr_lines:
        mtch = re.match(r"([0-9a-z]+)", l)
        if not mtch:
            continue
        out.append(int(mtch.group(1), 16))
    return out

def mitee_rela_relocs(ta_path:Path):
    raw = subprocess.check_output(
        f"readelf -r --use-dynamic --wide {ta_path}", shell=True
    ).decode()
    plt_off = raw.find("'PLT' relocation section")
    relr_off = raw.find("'RELA' relocation section")
    relr = raw[relr_off:plt_off]
    relr_lines = relr.split("\n")
    relr_lines = relr_lines[2:]
    out = []
    for l in relr_lines:
        mtch = re.match(r"([0-9a-z]+)", l)
        if not mtch:
            continue
        out.append(int(mtch.group(1), 16))
    return out

if __name__ == "__main__":
    mitee_read_relocs(sys.argv[1])
