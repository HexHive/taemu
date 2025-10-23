import subprocess
import sys
import re


def teegris_32_rel(ta_path):
    raw = subprocess.check_output(
        f"readelf -r --use-dynamic --wide {ta_path}", shell=True
    ).decode()
    rel_off = raw.find("'REL' relocation section")
    rel = raw[rel_off:]
    rel_lines = rel.split("\n")
    rel_lines = rel_lines[2:]
    out = []
    for l in rel_lines:
        mtch = re.match(r"([0-9a-z]+) +([0-9a-z]+) +R_ARM_RELATIVE", l)
        if not mtch:
            continue
        out.append(int(mtch.group(1), 16))
    return out


if __name__ == "__main__":
    print(teegris_32_rel(sys.argv[1]))
